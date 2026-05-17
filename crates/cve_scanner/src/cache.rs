use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CachedCveData {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: f32,
    pub cached_at: String,
}

pub struct CveCache { cache_dir: PathBuf }

impl CveCache {
    pub fn new(cache_dir: &str) -> Result<Self> {
        let path = PathBuf::from(cache_dir);
        if !path.exists() { fs::create_dir_all(&path).context("Failed to create cache dir")?; }
        Ok(Self { cache_dir: path })
    }

    fn cache_file_path(&self, cve_id: &str) -> PathBuf { self.cache_dir.join(format!("{}.json", cve_id)) }

    pub fn get(&self, cve_id: &str) -> Result<Option<CachedCveData>> {
        let path = self.cache_file_path(cve_id);
        if !path.exists() { return Ok(None); }
        let content = fs::read_to_string(&path)?;
        let data: CachedCveData = serde_json::from_str(&content)?;
        Ok(Some(data))
    }

    pub fn set(&self, cve_id: &str, description: String, cvss_score: f32) -> Result<()> {
        let data = CachedCveData {
            cve_id: cve_id.to_string(),
            description,
            cvss_score,
            cached_at: chrono::Local::now().to_rfc3339(),
        };
        let path = self.cache_file_path(cve_id);
        let json = serde_json::to_string_pretty(&data)?;
        fs::write(&path, json)?;
        Ok(())
    }

    pub fn clear(&self) -> Result<()> {
        if self.cache_dir.exists() {
            fs::remove_dir_all(&self.cache_dir)?;
            fs::create_dir_all(&self.cache_dir)?;
        }
        Ok(())
    }

    pub fn list_cached(&self) -> Result<Vec<String>> {
        let mut cves = Vec::new();
        if !self.cache_dir.exists() { return Ok(cves); }
        for entry in fs::read_dir(&self.cache_dir)? {
            let path = entry?.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Some(filename) = path.file_stem().and_then(|f| f.to_str()) {
                    cves.push(filename.to_string());
                }
            }
        }
        Ok(cves)
    }
}