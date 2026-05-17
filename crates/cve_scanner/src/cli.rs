use std::path::PathBuf;

/// Configuration CLI pour le scanner CVE
#[derive(Debug, Clone)]
pub struct Config {
    /// Fichier JSON d'entrée contenant les services
    pub input_file: PathBuf,
    
    /// Fichier JSON de sortie pour le rapport
    pub output_file: Option<PathBuf>,
    
    /// Dossier pour le cache local des CVE
    pub cache_dir: PathBuf,
    
    /// Activer l'interrogation de l'API NVD (vs. données locales)
    pub use_nvd: bool,
    
    /// Filtrer par sévérité minimale (LOW, MEDIUM, HIGH, CRITICAL)
    pub min_severity: Option<String>,
    
    /// Filtrer par score CVSS minimum
    pub min_cvss_score: Option<f32>,
}

impl Config {
    /// Parse les arguments de la ligne de commande
    pub fn from_args(args: Vec<String>) -> Result<Self, String> {
        if args.len() < 2 {
            return Err(
                "Usage: cve_scanner <input_file> [--output <file>] [--cache <dir>] [--nvd] [--min-severity LEVEL] [--min-cvss SCORE]".to_string()
            );
        }

        let input_file = PathBuf::from(&args[1]);
        let mut output_file = None;
        let mut cache_dir = PathBuf::from("./cache");
        let mut use_nvd = false;
        let mut min_severity = None;
        let mut min_cvss_score = None;

        // Créer le dossier cache s'il n'existe pas
        let _ = std::fs::create_dir_all(&cache_dir);

        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                "--output" => {
                    if i + 1 < args.len() {
                        output_file = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    } else {
                        return Err("--output requires a file path".to_string());
                    }
                }
                "--cache" => {
                    if i + 1 < args.len() {
                        cache_dir = PathBuf::from(&args[i + 1]);
                        i += 2;
                    } else {
                        return Err("--cache requires a directory path".to_string());
                    }
                }
                "--nvd" => {
                    use_nvd = true;
                    i += 1;
                }
                "--min-severity" => {
                    if i + 1 < args.len() {
                        min_severity = Some(args[i + 1].clone());
                        i += 2;
                    } else {
                        return Err("--min-severity requires a level".to_string());
                    }
                }
                "--min-cvss" => {
                    if i + 1 < args.len() {
                        min_cvss_score = args[i + 1]
                            .parse()
                            .map(Some)
                            .map_err(|_| "Invalid CVSS score".to_string())?;
                        i += 2;
                    } else {
                        return Err("--min-cvss requires a number".to_string());
                    }
                }
                _ => {
                    return Err(format!("Unknown argument: {}", args[i]));
                }
            }
        }

        Ok(Config {
            input_file,
            output_file,
            cache_dir,
            use_nvd,
            min_severity,
            min_cvss_score,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_basic() {
        let args = vec![
            "scanner".to_string(),
            "services.json".to_string(),
        ];
        let config = Config::from_args(args).unwrap();
        assert_eq!(config.input_file, PathBuf::from("services.json"));
        assert_eq!(config.cache_dir, PathBuf::from("./cache"));
        assert!(!config.use_nvd);
    }

    #[test]
    fn test_config_with_output() {
        let args = vec![
            "scanner".to_string(),
            "services.json".to_string(),
            "--output".to_string(),
            "report.json".to_string(),
        ];
        let config = Config::from_args(args).unwrap();
        assert_eq!(config.output_file, Some(PathBuf::from("report.json")));
    }

    #[test]
    fn test_config_with_nvd() {
        let args = vec![
            "scanner".to_string(),
            "services.json".to_string(),
            "--nvd".to_string(),
        ];
        let config = Config::from_args(args).unwrap();
        assert!(config.use_nvd);
    }

    #[test]
    fn test_config_with_filters() {
        let args = vec![
            "scanner".to_string(),
            "services.json".to_string(),
            "--min-severity".to_string(),
            "HIGH".to_string(),
            "--min-cvss".to_string(),
            "7.5".to_string(),
        ];
        let config = Config::from_args(args).unwrap();
        assert_eq!(config.min_severity, Some("HIGH".to_string()));
        assert_eq!(config.min_cvss_score, Some(7.5));
    }

    #[test]
    fn test_config_no_args() {
        let args = vec!["scanner".to_string()];
        let result = Config::from_args(args);
        assert!(result.is_err());
    }
}
