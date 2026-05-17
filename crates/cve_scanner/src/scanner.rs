use crate::models::{Service, Vulnerability, ScanReport};
use crate::data::get_cve_database;

/// Scanne une liste de services contre la base de CVE connus
/// Retourne un rapport avec les vulnérabilités trouvées
pub fn scan_services(services: Vec<Service>) -> ScanReport {
    let mut report = ScanReport::new(services);
    
    // Charger la base CVE
    let cve_db = get_cve_database();
    
    // Clone les services pour éviter les problèmes de borrow
    let scanned_services = report.scanned_services.clone();
    
    // Matcher chaque service contre les CVE
    for service in &scanned_services {
        for cve in &cve_db {
            // Matching: même nom de service ET version affectée
            if service.name == cve.service_name 
                && cve.affected_versions.contains(&service.version) 
            {
                report.add_vulnerability(cve.clone());
            }
        }
    }
    
    // Mettre à jour le résumé
    report.update_summary();
    report
}

/// Compte les vulnérabilités par sévérité
pub fn count_by_severity(report: &ScanReport) -> std::collections::HashMap<String, usize> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    
    for vuln in &report.vulnerabilities_found {
        *counts.entry(vuln.severity.clone()).or_insert(0) += 1;
    }
    
    counts
}

/// Filtre les vulnérabilités par sévérité minimale
pub fn filter_by_severity(report: &ScanReport, min_severity: &str) -> Vec<Vulnerability> {
    let severity_levels = vec!["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    let min_level = severity_levels.iter().position(|&s| s == min_severity).unwrap_or(0);
    
    report.vulnerabilities_found
        .iter()
        .filter(|v| {
            severity_levels
                .iter()
                .position(|&s| s == v.severity.as_str())
                .unwrap_or(0)
                >= min_level
        })
        .cloned()
        .collect()
}

/// Filtre les vulnérabilités par CVSS score minimum
pub fn filter_by_cvss_score(report: &ScanReport, min_score: f32) -> Vec<Vulnerability> {
    report.vulnerabilities_found
        .iter()
        .filter(|v| v.cvss_score >= min_score)
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_services_from_json;

    #[test]
    fn test_scan_finds_vulnerability() {
        let json = r#"{
            "services": [
                {"name": "Apache", "version": "2.4.49"}
            ]
        }"#;

        let services = load_services_from_json(json).unwrap();
        let report = scan_services(services);

        // Apache 2.4.49 = CVE-2021-41773
        assert_eq!(report.vulnerabilities_found.len(), 1);
        assert_eq!(report.vulnerabilities_found[0].cve_id, "CVE-2021-41773");
    }

    #[test]
    fn test_scan_no_vulnerabilities() {
        let json = r#"{
            "services": [
                {"name": "UnknownService", "version": "1.0.0"}
            ]
        }"#;

        let services = load_services_from_json(json).unwrap();
        let report = scan_services(services);

        assert_eq!(report.vulnerabilities_found.len(), 0);
    }

    #[test]
    fn test_count_by_severity() {
        let json = r#"{
            "services": [
                {"name": "Apache", "version": "2.4.49"},
                {"name": "Log4j", "version": "2.14.1"}
            ]
        }"#;

        let services = load_services_from_json(json).unwrap();
        let report = scan_services(services);

        let counts = count_by_severity(&report);
        assert_eq!(counts.get("CRITICAL").copied().unwrap_or(0), 2);
    }

    #[test]
    fn test_filter_by_severity() {
        let json = r#"{
            "services": [
                {"name": "Apache", "version": "2.4.49"},
                {"name": "OpenSSL", "version": "1.1.1"}
            ]
        }"#;

        let services = load_services_from_json(json).unwrap();
        let report = scan_services(services);

        // Filtrer pour CRITICAL et plus
        let critical = filter_by_severity(&report, "CRITICAL");
        // Apache 2.4.49 = CRITICAL
        assert!(critical.iter().any(|v| v.cve_id == "CVE-2021-41773"));
    }

    #[test]
    fn test_filter_by_cvss_score() {
        let json = r#"{
            "services": [
                {"name": "Apache", "version": "2.4.49"},
                {"name": "OpenSSL", "version": "1.1.1"}
            ]
        }"#;

        let services = load_services_from_json(json).unwrap();
        let report = scan_services(services);

        // Filtrer pour CVSS >= 9.0
        let high_severity = filter_by_cvss_score(&report, 9.0);
        // Apache 2.4.49 (9.8) et OpenSSL (7.5) → seulement Apache
        assert!(high_severity.iter().any(|v| v.cvss_score >= 9.0));
    }
}
