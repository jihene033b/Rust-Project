use std::io::Write;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::collections::HashSet;

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use tokio::sync::mpsc;

// Imports de vos crates internes du Workspace
use http_fuzzer::{FuzzerArgs, run_fuzzer};
use network_scanner::{PortInfo, ScanConfig, TOP_1000_PORTS, parse_ports, parse_targets, scan};
use cve_scanner::models::{Service, ServiceList};
use cve_scanner::nvd_client::NvdClient;

#[derive(Parser)]
#[command(name = "scanner", about = "Security tooling suite")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Fuzz {
        #[command(flatten)]
        args: FuzzerArgs,
    },

    Scan {
        #[arg(short, long)]
        target: String,

        #[arg(short, long)]
        ports: Option<String>,

        #[arg(long)]
        top_ports: Option<usize>,

        #[arg(short = 'T', long, default_value = "3", value_parser = clap::value_parser!(u8).range(0..=5))]
        timing: u8,

        #[arg(long = "no-ping")]
        no_ping: bool,

        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    Cve {
        /// Le chemin vers le fichier de rapport final (ex: ./data/outputs/cve_report.json)
        #[arg(short, long)]
        output: PathBuf,
    },
}

fn timing_config(level: u8) -> (usize, u64) {
    match level {
        0 => (1, 5000),
        1 => (10, 3000),
        2 => (50, 2000),
        3 => (1000, 1000),
        4 => (3000, 500),
        5 => (5000, 200),
        _ => (1000, 1000),
    }
}

/// Analyse une bannière réseau brute pour extraire le nom standardisé et la version épurée.
fn parse_known_service(banner: &str) -> Option<(String, String)> {
    if banner.contains("OpenSSH_") {
        if let Some(ver) = banner.split("OpenSSH_").nth(1).and_then(|s| s.split_whitespace().next()) {
            let clean_ver = match ver.find('p') {
                Some(idx) if ver[idx + 1..].chars().all(|c| c.is_ascii_digit()) => &ver[..idx],
                _ => ver,
            };
            return Some(("OpenSSH".to_string(), clean_ver.to_string()));
        }
    }
    if banner.contains("VMware Authentication Daemon Version") {
        if let Some(ver) = banner.split("Version ").nth(1).and_then(|s| s.split_whitespace().next()) {
            let clean_ver = ver.trim_end_matches(|c| c == ':' || c == ',').to_string();
            return Some(("VMware Authentication Daemon".to_string(), clean_ver));
        }
    }
    if let Some(idx) = banner.find("Apache/") {
        if let Some(ver) = banner[idx + 7..].split_whitespace().next() {
            let clean_ver = ver.trim_end_matches(|c| c == '(' || c == ')' || c == ',' || c == ':').to_string();
            return Some(("Apache HTTP Server".to_string(), clean_ver));
        }
    }
    if let Some(idx) = banner.find("nginx/") {
        if let Some(ver) = banner[idx + 6..].split_whitespace().next() {
            let clean_ver = ver.trim_end_matches(|c| c == ';' || c == ',').to_string();
            return Some(("Nginx".to_string(), clean_ver));
        }
    }
    if let Some(idx) = banner.find("Microsoft-IIS/") {
        if let Some(ver) = banner[idx + 14..].split_whitespace().next() {
            return Some(("Microsoft IIS".to_string(), ver.to_string()));
        }
    }
    if let Some(idx) = banner.find("Apache-Coyote/") {
        if let Some(ver) = banner[idx + 14..].split_whitespace().next() {
            return Some(("Apache Tomcat".to_string(), ver.to_string()));
        }
    }
    if let Some(idx) = banner.find("squid/") {
        if let Some(ver) = banner[idx + 6..].split_whitespace().next() {
            return Some(("Squid Proxy".to_string(), ver.to_string()));
        }
    }
    if let Some(idx) = banner.find("HAProxy/") {
        if let Some(ver) = banner[idx + 8..].split_whitespace().next() {
            return Some(("HAProxy".to_string(), ver.to_string()));
        }
    }
    if let Some(idx) = banner.find("lighttpd/") {
        if let Some(ver) = banner[idx + 9..].split_whitespace().next() {
            return Some(("Lighttpd".to_string(), ver.to_string()));
        }
    }
    if banner.contains("Postfix") {
        if let Some(idx) = banner.find("Postfix (") {
            if let Some(ver) = banner[idx + 9..].split(')').next() {
                return Some(("Postfix".to_string(), ver.to_string()));
            }
        }
        return Some(("Postfix".to_string(), "unknown".to_string()));
    }
    if banner.contains("Exim") {
        if let Some(ver) = banner.split("Exim ").nth(1).and_then(|s| s.split_whitespace().next()) {
            return Some(("Exim".to_string(), ver.to_string()));
        }
    }
    if banner.contains("Dovecot") { return Some(("Dovecot".to_string(), "unknown".to_string())); }
    if banner.contains("ProFTPD") {
        if let Some(ver) = banner.split("ProFTPD ").nth(1).and_then(|s| s.split_whitespace().next()) {
            return Some(("ProFTPD".to_string(), ver.to_string()));
        }
    }
    if banner.contains("vsFTPd") {
        if let Some(ver) = banner.split("vsFTPd ").nth(1).and_then(|s| s.split_whitespace().next()) {
            let clean_ver = ver.trim_end_matches(')').to_string();
            return Some(("vsftpd".to_string(), clean_ver));
        }
    }
    if banner.contains("Pure-FTPd") {
        if let Some(ver) = banner.split("Pure-FTPd ").nth(1).and_then(|s| s.split_whitespace().next()) {
            return Some(("Pure-FTPd".to_string(), ver.to_string()));
        }
    }
    if banner.contains("PostgreSQL") {
        if let Some(ver) = banner.split("PostgreSQL ").nth(1).and_then(|s| s.split_whitespace().next()) {
            return Some(("PostgreSQL".to_string(), ver.to_string()));
        }
        return Some(("PostgreSQL".to_string(), "unknown".to_string()));
    }
    if banner.contains("MariaDB") {
        if let Some(part) = banner.split("-MariaDB").next() {
            let ver = part.split_whitespace().last().unwrap_or("").trim_start_matches("5.5.5-");
            if !ver.is_empty() { return Some(("MariaDB".to_string(), ver.to_string())); }
        }
        return Some(("MariaDB".to_string(), "unknown".to_string()));
    }
    if banner.contains("MySQL") || banner.contains("mysql_native_password") {
        if let Some(ver) = banner.split_whitespace().next() {
            let clean_ver = ver.trim_start_matches("5.5.5-").to_string();
            return Some(("MySQL".to_string(), clean_ver));
        }
        return Some(("MySQL".to_string(), "unknown".to_string()));
    }
    if banner.contains("Zabbix") { return Some(("Zabbix".to_string(), "unknown".to_string())); }
    if banner.contains("OpenVPN") { return Some(("OpenVPN".to_string(), "unknown".to_string())); }

    None
}

/// Déclenche le pipeline complet de consolidation et d'interrogation de l'API NIST
pub async fn process_cve_pipeline(net_scanner_path: &Path, fuzzer_path: &Path, output_path: &Path) -> Result<()> {
    let mut unique_services = HashSet::new();

    // 1️⃣ Extraction et nettoyage des données de net_scanner.json
    if net_scanner_path.exists() {
        if let Ok(content) = std::fs::read_to_string(net_scanner_path) {
            #[derive(Deserialize)]
            struct TempPortInfo { service: String, banner: Option<String> }
            #[derive(Deserialize)]
            struct TempScanResult { open_ports: Vec<TempPortInfo> }

            if let Ok(results) = serde_json::from_str::<Vec<TempScanResult>>(&content) {
                for host in results {
                    for port in host.open_ports {
                        if let Some(ref banner) = port.banner {
                            if let Some((name, version)) = parse_known_service(banner) {
                                unique_services.insert(Service { name, version });
                                continue;
                            }
                            if banner.starts_with("HTTP/") { continue; }
                        }
                        if !port.service.is_empty() && port.service != "unknown" {
                            unique_services.insert(Service { name: port.service.clone(), version: "unknown".to_string() });
                        }
                    }
                }
            }
        }
    }

    // 2️⃣ Extraction et découpage des signatures du fuzzer
    if fuzzer_path.exists() {
        if let Ok(content) = std::fs::read_to_string(fuzzer_path) {
            #[derive(Deserialize)]
            struct TempFuzzerFinding { server: String }

            if let Ok(findings) = serde_json::from_str::<Vec<TempFuzzerFinding>>(&content) {
                for finding in findings {
                    if finding.server.contains('/') {
                        let parts: Vec<&str> = finding.server.split('/').collect();
                        if parts.len() == 2 {
                            unique_services.insert(Service {
                                name: parts[0].trim().to_string(),
                                version: parts[1].trim().to_string(),
                            });
                        }
                    } else if finding.server != "Inconnu" && !finding.server.is_empty() {
                        unique_services.insert(Service {
                            name: finding.server,
                            version: "unknown".to_string(),
                        });
                    }
                }
            }
        }
    }

    // 3️⃣ Enregistrement du JSON consolidé intermédiaire
    let services_vec: Vec<Service> = unique_services.into_iter().collect();
    let output_list = ServiceList { services: services_vec.clone() };

    let file = File::create(output_path)?;
    serde_json::to_writer_pretty(file, &output_list)?;
    println!("[+] Fichier des services consolidés enregistré dans : {:?}", output_path);

    // 4️⃣ Recherche asynchrone des CVEs via le client NVD réel
    println!("[*] Interrogation de l'API NVD du NIST en cours (Asynchrone)...");
    let nvd_client = NvdClient::new();
    let api_key: Option<&str> = None; 
    
    let vuln_reports = nvd_client.scan_services_for_cves(services_vec, api_key).await;

    // Sauvegarde du rapport final de vulnérabilités directement à l'emplacement demandé
    let vuln_file = File::create(output_path.with_file_name("cve_report.json"))?;
    serde_json::to_writer_pretty(vuln_file, &vuln_reports)?;
    println!("[+] Rapport de vulnérabilités NVD enregistré avec succès !");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Fuzz { args } => {
            println!("--- [ Configuration du Fuzzer ] ---");
            println!("Cible : {}", args.url);
            println!("-----------------------------------\n");
            run_fuzzer(args).await?;
        }

        // 🚀 LOGIQUE DU SCANNER RÉSEAU ADAPTÉE ET FONCTIONNELLE
        Commands::Scan {
            target,
            ports,
            top_ports,
            timing,
            no_ping,
            output,
        } => {
            if timing >= 4 {
                println!(
                    "  T{} est {} et peut surcharger le réseau ou déclencher des alertes IDS.",
                    timing,
                    if timing == 5 { "INSANE" } else { "AGRESSIF" }
                );
                print!("Continuer ? [y/N] : ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Annulé.");
                    return Ok(());
                }
            }

            let port_list: Vec<u16> = if let Some(p) = ports {
                parse_ports(&p)?
            } else if let Some(n) = top_ports {
                TOP_1000_PORTS.iter().take(n).copied().collect()
            } else {
                TOP_1000_PORTS.to_vec()
            };

            let (concurrency, timeout_ms) = timing_config(timing);
            let targets = parse_targets(&target)?;
            let total = targets.len();

            println!("--- [ Network Scanner ] ---");
            println!("Target  : {}", target);
            println!("Hosts   : {}", total);
            println!("Ports   : {}", port_list.len());
            println!("Timing  : T{}", timing);
            println!("Threads : {}", concurrency);
            println!("Timeout : {}ms", timeout_ms);
            println!("---------------------------\n");

            let config = ScanConfig {
                concurrency,
                timeout_ms,
                skip_ping: no_ping,
                ports: port_list,
                mode: network_scanner::ScanMode::TcpConnect, // Correction de l'erreur du champ manquant !
            };

            let (tx, mut rx) = mpsc::channel::<(String, PortInfo)>(256);

            println!("{:<10} {:<10} {:<16} {}", "PORT", "STATE", "SERVICE", "BANNER");
            println!("{}", "-".repeat(70));

            let printer = tokio::spawn(async move {
                while let Some((_ip, info)) = rx.recv().await {
                    let banner = info.banner.as_deref().unwrap_or("");
                    println!(
                        "{:<10} {:<10} {:<16} {}",
                        format!("{}/tcp", info.port),
                        info.state.to_string(),
                        info.service,
                        banner
                    );
                }
            });

            let results = scan(targets, config, tx).await?;
            printer.await?;

            println!("\n--- [ Résumé ] ---");
            for result in &results {
                println!(
                    "{} : {} open, {} closed, {} filtered",
                    result.ip,
                    result.open_ports.len(),
                    result.closed_count,
                    result.filtered_count,
                );
            }

            if let Some(output_path) = output {
                println!("\n[+] Écriture du rapport réseau JSON dans : {:?}", output_path);
                let filtered_results: Vec<&network_scanner::ScanResult> = results
                    .iter()
                    .filter(|res| !res.open_ports.is_empty())
                    .collect();

                let file = File::create(&output_path)?;
                serde_json::to_writer_pretty(file, &filtered_results)?;
                println!("[+] Rapport réseau généré avec succès !");
            }
        }

        Commands::Cve { output: _ } => {
            println!("\n--- [ Pipeline CVE Unifié & Intelligent ] ---");
            
            let net_json = Path::new("./data/outputs/net_scanner.json");
            let fuzz_json = Path::new("./data/outputs/scan_report.json");
            let consolidated_json = Path::new("./data/outputs/all_services.json");

            process_cve_pipeline(net_json, fuzz_json, consolidated_json).await?;
        }
    }

    Ok(())
}