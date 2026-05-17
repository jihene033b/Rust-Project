use anyhow::Result;
use std::fs;
use regex::Regex;

/// Formate un objet JSON en string avec indentation
pub fn format_json<T: serde::Serialize>(obj: &T) -> Result<String> {
    serde_json::to_string_pretty(obj)
        .map_err(|e| anyhow::anyhow!("Failed to format JSON: {}", e))
}

/// Trouve les fichiers correspondant à un pattern dans un dossier
/// Ex: "net_scanner.json" ou "scan_report.json"
pub fn find_files_by_pattern(dir: &str, pattern: &str) -> Result<Vec<String>> {
    let regex = Regex::new(pattern)?;
    let mut matching_files = Vec::new();

    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                if regex.is_match(&file_name) {
                    matching_files.push(file_name);
                }
            }
        }
    }

    Ok(matching_files)
}

/// Sauvegarde une string JSON formatée dans un fichier
pub fn save_json_file(path: &str, content: &str) -> Result<()> {
    fs::write(path, content)
        .map_err(|e| anyhow::anyhow!("Failed to write file {}: {}", path, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Serialize, Deserialize};

    #[derive(Serialize, Deserialize)]
    struct TestData {
        name: String,
        value: i32,
    }

    #[test]
    fn test_format_json() {
        let data = TestData {
            name: "test".to_string(),
            value: 42,
        };
        let json = format_json(&data).unwrap();
        assert!(json.contains("\"name\""));
        assert!(json.contains("\"test\""));
        assert!(json.contains("42"));
    }

    #[test]
    fn test_find_files_by_pattern() {
        let result = find_files_by_pattern(".", ".*\\.rs$");
        assert!(result.is_ok());
    }
}
