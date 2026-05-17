use anyhow::Result;
use std::fs;
use regex::Regex;

pub fn format_json<T: serde::Serialize>(obj: &T) -> Result<String> {
    serde_json::to_string_pretty(obj).map_err(|e| anyhow::anyhow!("Failed to format JSON: {}", e))
}

pub fn find_files_by_pattern(dir: &str, pattern: &str) -> Result<Vec<String>> {
    let regex = Regex::new(pattern)?;
    let mut matching_files = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(file_name) = entry.file_name().into_string() {
                if regex.is_match(&file_name) { matching_files.push(file_name); }
            }
        }
    }
    Ok(matching_files)
}

pub fn save_json_file(path: &str, content: &str) -> Result<()> {
    fs::write(path, content).map_err(|e| anyhow::anyhow!("Failed to write file {}: {}", path, e))?;
    Ok(())
}