use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use serde::Deserialize;
use crate::models::{Service, ServiceList};

/// Analyse une bannière réseau brute pour extraire le nom standardisé et la version épurée.
/// Gère 20 services courants des infrastructures d'entreprises européennes.
fn parse_known_service(banner: &str) -> Option<(String, String)> {
    // 1️⃣ OpenSSH (Administration Linux)
    if banner.contains("OpenSSH_") {
        if let Some(ver) = banner.split("OpenSSH_").nth(1).and_then(|s| s.split_whitespace().next()) {
            let clean_ver = match ver.find('p') {
                Some(idx) if ver[idx + 1..].chars().all(|c| c.is_ascii_digit()) => &ver[..idx],
                _ => ver,
            };
            return Some(("OpenSSH".to_string(), clean_ver.to_string()));
        }
    }
    
    // 2️⃣ VMware Authentication Daemon (Virtualisation d'infrastructure)
    if banner.contains("VMware Authentication Daemon Version") {
        if let Some(ver) = banner.split("Version ").nth(1).and_then(|s| s.split_whitespace().next()) {
            let clean_ver = ver.trim_end_matches(|c| c == ':' || c == ',').to_string();
            return Some(("VMware Authentication Daemon".to_string(), clean_ver));
        }
    }

    // 3️⃣ Apache HTTP Server (Serveur Web traditionnel)
    if let Some(idx) = banner.find("Apache/") {
        if let Some(ver) = banner[idx + 7..].split_whitespace().next() {
            let clean_ver = ver.trim_end_matches(|c| c == '(' || c == ')' || c == ',' || c == ':').to_string();
            return Some(("Apache HTTP Server".to_string(), clean_ver));
        }
    }

    // 4️⃣ Nginx (Serveur Web / Reverse Proxy ultra-courant)
    if let Some(idx) = banner.find("nginx/") {
        if let Some(ver) = banner[idx + 6..].split_whitespace().next() {
            let clean_ver = ver.trim_end_matches(|c| c == ';' || c == ',').to_string();
            return Some(("Nginx".to_string(), clean_ver));
        }
    }

    // 5️⃣ Microsoft IIS (Serveur Web d'infrastructure Windows Active Directory)
    if let Some(idx) = banner.find("Microsoft-IIS/") {
        if let Some(ver) = banner[idx + 14..].split_whitespace().next() {
            return Some(("Microsoft IIS".to_string(), ver.to_string()));
        }
    }

    // 6️⃣ Apache Tomcat / Coyote (Applications d'entreprise Java / Métier)
    if let Some(idx) = banner.find("Apache-Coyote/") {
        if let Some(ver) = banner[idx + 14..].split_whitespace().next() {
            return Some(("Apache Tomcat".to_string(), ver.to_string()));
        }
    }

    // 7️⃣ Squid Proxy (Proxy de filtrage web d'entreprise)
    if let Some(idx) = banner.find("squid/") {
        if let Some(ver) = banner[idx + 6..].split_whitespace().next() {
            return Some(("Squid Proxy".to_string(), ver.to_string()));
        }
    }

    // 8️⃣ HAProxy (Répartition de charge / Haute disponibilité)
    if let Some(idx) = banner.find("HAProxy/") {
        if let Some(ver) = banner[idx + 8..].split_whitespace().next() {
            return Some(("HAProxy".to_string(), ver.to_string()));
        }
    }

    // 9️⃣ Lighttpd (Serveur web léger embarqué dans les appliances / routeurs)
    if let Some(idx) = banner.find("lighttpd/") {
        if let Some(ver) = banner[idx + 9..].split_whitespace().next() {
            return Some(("Lighttpd".to_string(), ver.to_string()));
        }
    }

    // 🔟 Postfix (Serveur de messagerie / Relais SMTP Linux standard en Europe)
    if banner.contains("Postfix") {
        if let Some(idx) = banner.find("Postfix (") {
            if let Some(ver) = banner[idx + 9..].split(')').next() {
                return Some(("Postfix".to_string(), ver.to_string()));
            }
        }
        return Some(("Postfix".to_string(), "unknown".to_string()));
    }

    // 1️⃣1️⃣ Exim (Autre serveur de messagerie SMTP très répandu)
    if banner.contains("Exim") {
        if let Some(ver) = banner.split("Exim ").nth(1).and_then(|s| s.split_whitespace().next()) {
            return Some(("Exim".to_string(), ver.to_string()));
        }
    }

    // 1️⃣2️⃣ Dovecot (Serveur de boîtes aux lettres IMAP/POP3 d'entreprise)
    if banner.contains("Dovecot") {
        return Some(("Dovecot".to_string(), "unknown".to_string()));
    }

    // 1️⃣3️⃣ ProFTPD (Partage de fichiers / FTP d'entreprise hérité)
    if banner.contains("ProFTPD") {
        if let Some(ver) = banner.split("ProFTPD ").nth(1).and_then(|s| s.split_whitespace().next()) {
            return Some(("ProFTPD".to_string(), ver.to_string()));
        }
    }

    // 1️⃣4️⃣ vsftpd (Very Secure FTP Daemon)
    if banner.contains("vsFTPd") {
        if let Some(ver) = banner.split("vsFTPd ").nth(1).and_then(|s| s.split_whitespace().next()) {
            let clean_ver = ver.trim_end_matches(')').to_string();
            return Some(("vsftpd".to_string(), clean_ver));
        }
    }

    // 1️⃣5️⃣ Pure-FTPd (Autre serveur FTP industriel courant)
    if banner.contains("Pure-FTPd") {
        if let Some(ver) = banner.split("Pure-FTPd ").nth(1).and_then(|s| s.split_whitespace().next()) {
            return Some(("Pure-FTPd".to_string(), ver.to_string()));
        }
    }

    // 1️⃣6️⃣ PostgreSQL (La base de données Open-Source reine en entreprise)
    if banner.contains("PostgreSQL") {
        if let Some(ver) = banner.split("PostgreSQL ").nth(1).and_then(|s| s.split_whitespace().next()) {
            return Some(("PostgreSQL".to_string(), ver.to_string()));
        }
        return Some(("PostgreSQL".to_string(), "unknown".to_string()));
    }

    // 1️⃣7️⃣ MariaDB (Base de données relationnelle alternative à MySQL)
    if banner.contains("MariaDB") {
        if let Some(part) = banner.split("-MariaDB").next() {
            let ver = part.split_whitespace().last().unwrap_or("").trim_start_matches("5.5.5-");
            if !ver.is_empty() {
                return Some(("MariaDB".to_string(), ver.to_string()));
            }
        }
        return Some(("MariaDB".to_string(), "unknown".to_string()));
    }

    // 1️⃣8️⃣ MySQL (Base de données relationnelle Oracle)
    if banner.contains("MySQL") || banner.contains("mysql_native_password") {
        if let Some(ver) = banner.split_whitespace().next() {
            let clean_ver = ver.trim_start_matches("5.5.5-").to_string();
            return Some(("MySQL".to_string(), clean_ver));
        }
        return Some(("MySQL".to_string(), "unknown".to_string()));
    }

    // 1️⃣9️⃣ Zabbix Agent / Server (Supervision et monitoring d'infrastructure très populaire en Europe)
    if banner.contains("Zabbix") {
        return Some(("Zabbix".to_string(), "unknown".to_string()));
    }

    // 2️⃣0️⃣ OpenVPN (Passerelle d'accès distant / Télétravail)
    if banner.contains("OpenVPN") {
        return Some(("OpenVPN".to_string(), "unknown".to_string()));
    }

    None
}

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
                        if let Some(ref banner) = port.banner {
                            // Tente d'extraire et nettoyer le service via le dictionnaire de bannières connues
                            if let Some((name, version)) = parse_known_service(banner) {
                                unique_services.insert(Service { name, version });
                                continue;
                            }

                            // Les bannières HTTP génériques non matchées par la fonction sont ignorées
                            // car traitées avec plus de précision par le fuzzer applicatif
                            if banner.starts_with("HTTP/") {
                                continue;
                            }
                        }
                        
                        // Fallback si pas de bannière ou service inconnu de notre parseur, mais reconnu par nmap par défaut
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