use crate::models::{Service, Vulnerability, ScanReport};
use crate::data::get_cve_database;

pub fn scan_services(services: Vec<Service>) -> ScanReport {
    let mut report = ScanReport::new(services);
    let cve_db = get_cve_database();
    let scanned_services = report.scanned_services.clone();
    
    for service in &scanned_services {
        for cve in &cve_db {
            if service.name == cve.service_name 
                && cve.affected_versions.contains(&service.version) 
            {
                report.add_vulnerability(cve.clone());
            }
        }
    }
    
    report.update_summary();
    report
}

pub fn count_by_severity(report: &ScanReport) -> std::collections::HashMap<String, usize> {
    let mut counts = std::collections::HashMap::new();
    for vuln in &report.vulnerabilities_found {
        *counts.entry(vuln.severity.clone()).or_insert(0) += 1;
    }
    counts
}

pub fn filter_by_severity(report: &ScanReport, min_severity: &str) -> Vec<Vulnerability> {
    let severity_levels = vec!["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    let min_level = severity_levels.iter().position(|&s| s == min_severity).unwrap_or(0);
    
    report.vulnerabilities_found
        .iter()
        .filter(|v| {
            severity_levels.iter().position(|&s| s == v.severity.as_str()).unwrap_or(0) >= min_level
        })
        .cloned()
        .collect()
}

pub fn filter_by_cvss_score(report: &ScanReport, min_score: f32) -> Vec<Vulnerability> {
    report.vulnerabilities_found.iter().filter(|v| v.cvss_score >= min_score).cloned().collect()
}