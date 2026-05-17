use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Cache local pour les données NVD
/// Format: cache/CVE-YYYY-XXXX.json
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CachedCveData {
    pub cve_id: String,
    pub description: String,
    pub cvss_score: f32,
    pub cached_at: String, // ISO 8601 timestamp
}

pub struct CveCache {
    cache_dir: PathBuf,
}

impl CveCache {
    /// Crée un nouveau cache dans le dossier spécifié
    pub fn new(cache_dir: &str) -> Result<Self> {
        let path = PathBuf::from(cache_dir);
        
        // Créer le dossier s'il n'existe pas
        if !path.exists() {
            fs::create_dir_all(&path)
                .context(format!("Failed to create cache directory: {}", cache_dir))?;
        }
        
        Ok(Self { cache_dir: path })
    }

    /// Chemin du fichier cache pour une CVE
    fn cache_file_path(&self, cve_id: &str) -> PathBuf {
        self.cache_dir.join(format!("{}.json", cve_id))
    }

    /// Lit une CVE du cache
    pub fn get(&self, cve_id: &str) -> Result<Option<CachedCveData>> {
        let path = self.cache_file_path(cve_id);
        
        if !path.exists() {
            return Ok(None);
        }
        
        let content = fs::read_to_string(&path)
            .context(format!("Failed to read cache file: {:?}", path))?;
        
        let data: CachedCveData = serde_json::from_str(&content)
            .context("Failed to parse cached CVE data")?;
        
        Ok(Some(data))
    }

    /// Écrit une CVE dans le cache
    pub fn set(&self, cve_id: &str, description: String, cvss_score: f32) -> Result<()> {
        let data = CachedCveData {
            cve_id: cve_id.to_string(),
            description,
            cvss_score,
            cached_at: chrono::Local::now().to_rfc3339(),
        };
        
        let path = self.cache_file_path(cve_id);
        let json = serde_json::to_string_pretty(&data)
            .context("Failed to serialize CVE data")?;
        
        fs::write(&path, json)
            .context(format!("Failed to write cache file: {:?}", path))?;
        
        Ok(())
    }

    /// Vide complètement le cache
    pub fn clear(&self) -> Result<()> {
        if self.cache_dir.exists() {
            fs::remove_dir_all(&self.cache_dir)
                .context("Failed to clear cache directory")?;
            fs::create_dir_all(&self.cache_dir)
                .context("Failed to recreate cache directory")?;
        }
        Ok(())
    }

    /// Liste toutes les CVE en cache
    pub fn list_cached(&self) -> Result<Vec<String>> {
        let mut cves = Vec::new();
        
        if !self.cache_dir.exists() {
            return Ok(cves);
        }
        
        for entry in fs::read_dir(&self.cache_dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Some(filename) = path.file_stem() {
                    if let Some(name_str) = filename.to_str() {
                        cves.push(name_str.to_string());
                    }
                }
            }
        }
        
        Ok(cves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_cache_creation() {
        let temp_dir = TempDir::new().unwrap();
        let cache = CveCache::new(temp_dir.path().to_str().unwrap()).unwrap();
        assert!(temp_dir.path().exists());
    }

    #[test]
    fn test_cache_set_get() {
        let temp_dir = TempDir::new().unwrap();
        let cache = CveCache::new(temp_dir.path().to_str().unwrap()).unwrap();

        // Set
        cache
            .set(
                "CVE-2021-41773",
                "Test description".to_string(),
                9.8,
            )
            .unwrap();

        // Get
        let result = cache.get("CVE-2021-41773").unwrap();
        assert!(result.is_some());
        
        let data = result.unwrap();
        assert_eq!(data.cve_id, "CVE-2021-41773");
        assert_eq!(data.description, "Test description");
        assert_eq!(data.cvss_score, 9.8);
    }

    #[test]
    fn test_cache_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let cache = CveCache::new(temp_dir.path().to_str().unwrap()).unwrap();

        let result = cache.get("CVE-9999-99999").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_list() {
        let temp_dir = TempDir::new().unwrap();
        let cache = CveCache::new(temp_dir.path().to_str().unwrap()).unwrap();

        cache
            .set("CVE-2021-41773", "Test 1".to_string(), 9.8)
            .unwrap();
        cache
            .set("CVE-2021-44228", "Test 2".to_string(), 10.0)
            .unwrap();

        let list = cache.list_cached().unwrap();
        assert_eq!(list.len(), 2);
        assert!(list.contains(&"CVE-2021-41773".to_string()));
        assert!(list.contains(&"CVE-2021-44228".to_string()));
    }

    #[test]
    fn test_cache_clear() {
        let temp_dir = TempDir::new().unwrap();
        let cache = CveCache::new(temp_dir.path().to_str().unwrap()).unwrap();

        cache
            .set("CVE-2021-41773", "Test".to_string(), 9.8)
            .unwrap();
        assert_eq!(cache.list_cached().unwrap().len(), 1);

        cache.clear().unwrap();
        assert_eq!(cache.list_cached().unwrap().len(), 0);
    }
}
