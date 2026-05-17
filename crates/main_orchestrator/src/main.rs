use std::io::Write;
use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json;
use tokio::sync::mpsc;

// Imports de vos crates internes du Workspace
use http_fuzzer::{FuzzerArgs, run_fuzzer};
use network_scanner::{PortInfo, ScanConfig, TOP_1000_PORTS, parse_ports, parse_targets, scan};

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

    /// Centralise les rapports réseau/web et cherche les vulnérabilités correspondantes
    Cve {
        /// Le chemin vers le fichier de rapport final (ex: ./data/outputs/cve_report.json)
        #[arg(short, long)]
        output: PathBuf,

        /// Activer l'interrogation et l'enrichissement en temps réel via l'API NVD du NIST
        #[arg(long)]
        nvd: bool,
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

        Commands::Scan {
            target,
            ports,
            top_ports,
            timing,
            no_ping,
            output,
        } => {
            // Sécurité pour les modes agressifs
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

            // Sélection des ports
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
                mode: network_scanner::ScanMode::TcpConnect, // ou SynScan selon vos fonctionnalités
            };

            // Canal mpsc pour l'affichage temps réel
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

            // Lancement du scan
            let results = scan(targets, config, tx).await?;
            printer.await?;

            println!("\n--- [ Résumé du Scan ] ---");
            for result in &results {
                println!(
                    "{} : {} open, {} closed, {} filtered",
                    result.ip,
                    result.open_ports.len(),
                    result.closed_count,
                    result.filtered_count,
                );
            }

            // Exportation propre sans hôtes vides
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

        Commands::Cve { output, nvd } => {
            println!("\n--- [ 1. Normalisation & Centralisation des Services ] ---");
            let net_json = Path::new("./data/outputs/net_scanner.json");
            let fuzz_json = Path::new("./data/outputs/scan_report.json");
            let all_services_json = Path::new("./data/outputs/all_services.json");

            // Extraction et création de all_services.json unifié
            cve_scanner::generate_all_services_json(net_json, fuzz_json, all_services_json)?;

            println!("\n--- [ 2. Analyse Initiale (Local matching) ] ---");
            let services = cve_scanner::loader::load_services_from_file("./data/outputs/all_services.json")?;
            println!("[+] {} composants uniques identifiés.", services.len());

            let mut report = cve_scanner::scanner::scan_services(services);

            // 🚀 ENRICHISSEMENT ET INTERROGATION EN LIGNE VIA LE CODE DE TON AMI
            if nvd {
                println!("\n--- [ 3. Interrogation de la base NVD du NIST (Cache actif) ] ---");
                let cache = cve_scanner::CveCache::new("./cache")?;
                let nvd_client = cve_scanner::NvdClient::new();

                for vuln in &mut report.vulnerabilities_found {
                    print!(" -> Analyse de {} ... ", vuln.cve_id);
                    std::io::stdout().flush()?;

                    // Étape 1 : On regarde si la CVE est déjà documentée dans notre cache local
                    if let Ok(Some(cached_data)) = cache.get(&vuln.cve_id) {
                        println!("(Hit Cache 📦)");
                        vuln.description = cached_data.description;
                        vuln.cvss_score = cached_data.cvss_score;
                    } else {
                        // Étape 2 : Sinon, on appelle l'API officielle
                        println!("(Requête API NVD 🌐)");
                        if let Err(e) = nvd_client.enrich_vulnerability(vuln).await {
                            eprintln!("    [⚠️ Erreur NVD] Impossible de joindre le NIST pour {} : {}", vuln.cve_id, e);
                        } else {
                            // Étape 3 : On stocke le résultat pour les prochaines fois
                            let _ = cache.set(&vuln.cve_id, vuln.description.clone(), vuln.cvss_score);
                        }
                    }
                }
            }

            println!("\n--- [ 4. Génération du Rapport Final ] ---");
            // Utilisation des fonctions de sauvegarde de ton collègue
            let json_content = cve_scanner::format_json(&report.vulnerabilities_found)?;
            let output_str = output.to_string_lossy();
            cve_scanner::save_json_file(&output_str, &json_content)?;
            
            println!("[+] Livrable de vulnérabilités mis à jour avec succès : {:?}", output);
        }
    }

    Ok(())
}