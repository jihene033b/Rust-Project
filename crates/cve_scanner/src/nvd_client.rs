use serde::{Deserialize, Serialize};
use crate::models::Service;
use anyhow::{Context, Result};

// ---- Structures de désérialisation pour l'API NVD v2 ----

#[derive(Deserialize, Debug)]
pub struct NvdV2Response {
    pub vulnerabilities: Option<Vec<NistVulnerability>>,
}

#[derive(Deserialize, Debug)]
pub struct NistVulnerability {
    pub cve: CveDetails,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct CveDetails {
    pub id: String,
    pub descriptions: Vec<CveDescription>,
    pub metrics: Option<CveMetrics>,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct CveDescription {
    pub lang: String,
    pub value: String,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct CveMetrics {
    #[serde(rename = "cvssMetricV31")]
    pub cvss_v31: Option<Vec<CvssMetricV31>>,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct CvssMetricV31 {
    #[serde(rename = "cvssData")]
    pub cvss_data: CvssData,
}

#[derive(Deserialize, Debug, Serialize, Clone)]
pub struct CvssData {
    #[serde(rename = "baseScore")]
    pub base_score: f32,
    #[serde(rename = "baseSeverity")]
    pub base_severity: String,
}

// ---- Structure du rapport final généré ----

#[derive(Serialize, Debug)]
pub struct VulnerabilityReport {
    pub service_name: String,
    pub version: String,
    pub cves: Vec<CveDetails>,
}

pub struct NvdClient {
    client: reqwest::Client,
}

impl NvdClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .user_agent("Rust-Vuln-Scanner/1.0")
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    /// Nouvelle méthode : Recherche des CVEs par mot-clé (Produit + Version) via API v2
    pub async fn scan_services_for_cves(&self, services: Vec<Service>, api_key: Option<&str>) -> Vec<VulnerabilityReport> {
        let mut reports = Vec::new();
        println!("\n[+] Lancement de la recherche de CVE sur la base NIST (Async)...");

        for service in services {
            if service.version == "unknown" || service.version.is_empty() {
                continue;
            }

            println!("[-] Recherche pour : {} {}", service.name, service.version);
            let keyword = format!("{} {}", service.name, service.version);
            let url = "https://services.nvd.nist.gov/rest/json/cves/2.0";

            let mut req = self.client.get(url).query(&[("keywordSearch", &keyword)]);
            if let Some(key) = api_key {
                req = req.header("apiKey", key);
            }

            match req.send().await {
                Ok(response) => {
                    if response.status().is_success() {
                        if let Ok(nist_data) = response.json::<NvdV2Response>().await {
                            let mut discovered_cves = Vec::new();
                            if let Some(vulns) = nist_data.vulnerabilities {
                                for vuln in vulns {
                                    discovered_cves.push(vuln.cve);
                                }
                            }

                            if !discovered_cves.is_empty() {
                                println!("    ↳ [!] {} CVE(s) trouvée(s) !", discovered_cves.len());
                                reports.push(VulnerabilityReport {
                                    service_name: service.name,
                                    version: service.version,
                                    cves: discovered_cves,
                                });
                            } else {
                                println!("    ↳ [~] Aucune CVE trouvée.");
                            }
                        }
                    } else if response.status().as_u16() == 429 {
                        println!("    ↳ [x] Erreur 429 : Rate limit. Temporisation...");
                        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                    } else {
                        println!("    ↳ [x] Erreur API NVD : Code {}", response.status());
                    }
                }
                Err(e) => println!("    ↳ [x] Erreur réseau : {}", e),
            }

            // Rate limiting respectueux (6s sans clé, 1s avec clé)
            let delay = if api_key.is_some() { 1 } else { 6 };
            tokio::time::sleep(tokio::time::Duration::from_secs(delay)).await;
        }

        reports
    }
}