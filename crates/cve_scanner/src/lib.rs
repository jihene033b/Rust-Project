pub mod models;
pub mod data;
pub mod loader;
pub mod scanner;

// Re-export les types principaux pour faciliter l'utilisation
pub use models::{Service, Vulnerability, ServiceList, ScanReport};
pub use loader::{load_services_from_file, load_services_from_json};
pub use data::get_cve_database;
pub use scanner::{scan_services, count_by_severity, filter_by_severity, filter_by_cvss_score};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_vulnerability_detection() {
        // Test complet: Charger services → Comparer avec CVE → Générer rapport
        
        let json = r#"{
            "services": [
                {"name": "Apache", "version": "2.4.49"},
                {"name": "OpenSSL", "version": "1.1.1g"}
            ]
        }"#;

        // 1️⃣ Charger les services depuis JSON
        let services = load_services_from_json(json)
            .expect("Failed to load services");
        assert_eq!(services.len(), 2);

        // 2️⃣ Utiliser le scanner
        let report = scan_services(services);

        // Apache 2.4.49 devrait avoir CVE-2021-41773
        assert_eq!(report.vulnerabilities_found.len(), 1);
        assert_eq!(
            report.vulnerabilities_found[0].cve_id,
            "CVE-2021-41773"
        );
    }

    #[test]
    fn test_no_vulnerabilities_found() {
        let json = r#"{
            "services": [
                {"name": "UnknownService", "version": "1.0.0"}
            ]
        }"#;

        let services = load_services_from_json(json)
            .expect("Failed to load services");
        let report = scan_services(services);

        assert_eq!(report.vulnerabilities_found.len(), 0);
        assert_eq!(report.summary, "No vulnerabilities found");
    }

    #[test]
    fn test_multiple_vulnerabilities() {
        // OpenSSL 1.1.1 a 2 CVE affectées
        let json = r#"{
            "services": [
                {"name": "OpenSSL", "version": "1.1.1"}
            ]
        }"#;

        let services = load_services_from_json(json)
            .expect("Failed to load services");
        let report = scan_services(services);

        // OpenSSL 1.1.1 → CVE-2022-0778 + CVE-2023-0215
        assert!(report.vulnerabilities_found.len() >= 2);
    }

    #[test]
    fn test_critical_and_high_severity() {
        let json = r#"{
            "services": [
                {"name": "Apache", "version": "2.4.49"},
                {"name": "Log4j", "version": "2.14.1"}
            ]
        }"#;

        let services = load_services_from_json(json)
            .expect("Failed to load services");
        let report = scan_services(services);

        // Apache 2.4.49 + Log4j 2.14.1 = 2 CRITICAL
        assert_eq!(report.vulnerabilities_found.len(), 2);
        
        let critical_count = report.vulnerabilities_found
            .iter()
            .filter(|v| v.severity == "CRITICAL")
            .count();
        assert_eq!(critical_count, 2);
    }
}
