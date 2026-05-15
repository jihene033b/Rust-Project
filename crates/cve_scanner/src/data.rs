use crate::models::Vulnerability;

/// Base de CVE factices pour tester le matching
pub fn get_cve_database() -> Vec<Vulnerability> {
    vec![
        Vulnerability {
            cve_id: "CVE-2021-41773".to_string(),
            service_name: "Apache".to_string(),
            affected_versions: vec!["2.4.49".to_string(), "2.4.50".to_string()],
            description: "Path Traversal & Remote Code Execution in Apache HTTP Server 2.4.49 and 2.4.50".to_string(),
            severity: "CRITICAL".to_string(),
            cvss_score: 9.8,
        },
        Vulnerability {
            cve_id: "CVE-2021-44228".to_string(),
            service_name: "Log4j".to_string(),
            affected_versions: vec!["2.0-beta9".to_string(), "2.14.1".to_string(), "2.15.0".to_string()],
            description: "Remote Code Execution in Apache Log4j".to_string(),
            severity: "CRITICAL".to_string(),
            cvss_score: 10.0,
        },
        Vulnerability {
            cve_id: "CVE-2022-0778".to_string(),
            service_name: "OpenSSL".to_string(),
            affected_versions: vec!["1.0.2".to_string(), "1.1.1".to_string(), "3.0.0".to_string(), "3.0.1".to_string()],
            description: "Infinite Loop in BN_mod_sqrt() in OpenSSL".to_string(),
            severity: "HIGH".to_string(),
            cvss_score: 7.5,
        },
        Vulnerability {
            cve_id: "CVE-2023-0215".to_string(),
            service_name: "OpenSSL".to_string(),
            affected_versions: vec!["1.0.2".to_string(), "1.1.1".to_string()],
            description: "Use After Free in X.509 certificate verification".to_string(),
            severity: "HIGH".to_string(),
            cvss_score: 7.5,
        },
        Vulnerability {
            cve_id: "CVE-2024-1086".to_string(),
            service_name: "nginx".to_string(),
            affected_versions: vec!["1.20.0".to_string(), "1.22.0".to_string()],
            description: "Privilege escalation in nginx HTTP/2 module".to_string(),
            severity: "HIGH".to_string(),
            cvss_score: 8.1,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cve_database_not_empty() {
        let db = get_cve_database();
        assert!(!db.is_empty());
        assert_eq!(db.len(), 5);
    }

    #[test]
    fn test_cve_database_valid() {
        let db = get_cve_database();
        for cve in db {
            assert!(!cve.cve_id.is_empty());
            assert!(!cve.service_name.is_empty());
            assert!(!cve.affected_versions.is_empty());
        }
    }
}
