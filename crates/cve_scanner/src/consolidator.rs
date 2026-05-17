use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use serde::Deserialize;
use crate::models::{Service, ServiceList};

/// Analyse les rapports du scanner de ports et du fuzzer pour générer un fichier global normalisé
pub fn generate_all_services_json(net_scanner_path: &Path, fuzzer_path: &Path, output_path: &Path) -> anyhow::Result<()> {
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
                        if let Some(banner) = port.banner {
                            // Cas OpenSSH : "SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u2"
                            if banner.contains("OpenSSH_") {
                                if let Some(ver) = banner.split("OpenSSH_").nth(1).and_then(|s| s.split_whitespace().next()) {
                                    unique_services.insert(Service { name: "OpenSSH".to_string(), version: ver.to_string() });
                                    continue;
                                }
                            }
                            // Cas VMware : "220 VMware Authentication Daemon Version 1.10: ..."
                            if banner.contains("VMware Authentication Daemon Version") {
                                if let Some(ver) = banner.split("Version ").nth(1).and_then(|s| s.split_whitespace().next()) {
                                    let clean_ver = ver.trim_end_matches(':').to_string();
                                    unique_services.insert(Service { name: "VMware Authentication Daemon".to_string(), version: clean_ver });
                                    continue;
                                }
                            }
                            // Les bannières HTTP génériques sont ignorées car traitées avec précision par le fuzzer
                            if banner.starts_with("HTTP/") {
                                continue;
                            }
                        }
                        // Fallback si pas de bannière mais que le service est reconnu
                        if !port.service.is_empty() && port.service != "unknown" {
                            unique_services.insert(Service { name: port.service.clone(), version: "unknown".to_string() });
                        }
                    }
                }
            }
        }
    }

    // 2️⃣ Extraction et découpage des signatures du fuzzer (ex: "nginx/1.29.1")
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

    // 3️⃣ Enregistrement au format demandé par l'API
    let output_list = ServiceList {
        services: unique_services.into_iter().collect(),
    };

    let file = File::create(output_path)?;
    serde_json::to_writer_pretty(file, &output_list)?;
    Ok(())
}