use crate::models::{Service, ServiceList};
use anyhow::{Context, Result};
use std::fs;

pub fn load_services_from_file(path: &str) -> Result<Vec<Service>> {
    let content = fs::read_to_string(path)
        .context(format!("Failed to read file: {}", path))?;
    
    load_services_from_json(&content)
}

pub fn load_services_from_json(json_str: &str) -> Result<Vec<Service>> {
    let service_list: ServiceList = serde_json::from_str(json_str)
        .context("Failed to parse JSON as ServiceList")?;
    
    Ok(service_list.services)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_services_from_json_valid() {
        let json = r#"{
            "services": [
                {"name": "Apache", "version": "2.4.41"},
                {"name": "OpenSSL", "version": "1.1.1g"}
            ]
        }"#;

        let services = load_services_from_json(json).unwrap();
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].name, "Apache");
        assert_eq!(services[0].version, "2.4.41");
    }
}