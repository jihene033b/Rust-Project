use serde::{Deserialize, Serialize};

/// Représente un service trouvé sur la machine (ex: Apache 2.4.41)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Service {
    pub name: String,
    pub version: String,
}

/// Représente une vulnérabilité CVE
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Vulnerability {
    pub cve_id: String,
    pub service_name: String,
    pub affected_versions: Vec<String>, // ex: ["1.1.0", "1.1.1f"]
    pub description: String,
    pub severity: String, // LOW, MEDIUM, HIGH, CRITICAL
    pub cvss_score: f32,
}

/// Wrapper pour charger et exporter un ensemble de services depuis/vers du JSON
#[derive(Debug, Deserialize, Serialize)]
pub struct ServiceList {
    pub services: Vec<Service>,
}

/// Rapport de scan: services analysés + vulnérabilités trouvées
#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub scanned_services: Vec<Service>,
    pub vulnerabilities_found: Vec<Vulnerability>,
    pub summary: String,
}

impl ScanReport {
    pub fn new(scanned_services: Vec<Service>) -> Self {
        Self {
            scanned_services,
            vulnerabilities_found: Vec::new(),
            summary: "No vulnerabilities found".to_string(),
        }
    }

    pub fn add_vulnerability(&mut self, vuln: Vulnerability) {
        self.vulnerabilities_found.push(vuln);
    }

    pub fn update_summary(&mut self) {
        let count = self.vulnerabilities_found.len();
        self.summary = match count {
            0 => "No vulnerabilities found".to_string(),
            1 => "1 vulnerability found".to_string(),
            n => format!("{} vulnerabilities found", n),
        };
    }
}