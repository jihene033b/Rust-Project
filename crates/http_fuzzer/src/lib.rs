use clap::Parser;
use std::path::PathBuf;
use std::fs::File;
use std::io::{BufRead, BufReader};
use reqwest::Client;
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use tokio::sync::Semaphore;
use serde::Serialize; // Import pour la sérialisation JSON

/// Structure représentant une découverte (vulnérable/existante)
#[derive(Serialize, Debug, Clone)]
pub struct FuzzerFinding {
    pub path: String,
    pub url: String,
    pub status: u16,
    pub server: String,
}

#[derive(Parser, Debug, Clone)]
#[command(name = "gobuster-rs")]
#[command(author = "Quentin GUILLAUME")]
#[command(version = "0.1.0")]
#[command(about = "Un fuzzer HTTP asynchrone ultra-rapide écrit en Rust", long_about = None)]
pub struct FuzzerArgs {
    #[arg(short, long, required = true)]
    pub url: String,

    #[arg(short, long, required = true)]
    pub wordlist: PathBuf,

    #[arg(short, long, default_value_t = 40)]
    pub threads: usize,

    #[arg(short, long, default_value = "200,204,301,302,307,401,403")]
    pub status_codes: String,

    #[arg(short = 'x', long)]
    pub extensions: Option<String>,

    /// Fichier de sortie pour le rapport JSON (ex: data/outputs/scan.json)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    #[arg(short = 'a', long, default_value = "Mozilla/5.0 (Gobuster-RS)")]
    pub user_agent: String,

    #[arg(short, long)]
    pub verbose: bool,
}

impl FuzzerArgs {
    pub fn parse_cli() -> Self {
        Self::parse()
    }

    pub fn get_status_codes(&self) -> Vec<u16> {
        self.status_codes
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
    }

    pub fn get_extensions(&self) -> Vec<String> {
        match &self.extensions {
            Some(exts) => exts
                .split(',')
                .map(|s| s.trim().trim_start_matches('.').to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            None => vec![],
        }
    }
}

pub fn read_wordlist(path: &std::path::Path) -> Result<Vec<String>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    
    let words = reader
        .lines()
        .filter_map(|line| line.ok())
        .map(|w| w.trim().to_string())
        .filter(|w| !w.is_empty())
        .collect();
        
    Ok(words)
}

pub async fn run_fuzzer(args: FuzzerArgs) -> Result<(), anyhow::Error> {
    println!("[+] Chargement de la wordlist...");
    let words = read_wordlist(&args.wordlist)?;
    
    let extensions = args.get_extensions();
    let total_requests = words.len() * (1 + extensions.len());
    
    println!("[+] {} mots chargés. Total estimé : {} requêtes.", words.len(), total_requests);
    println!("[+] Initialisation du scan...");

    let timeout_duration = std::time::Duration::from_secs(5);

    let client = Client::builder()
        .user_agent(&args.user_agent)
        .timeout(timeout_duration)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let client = Arc::new(client);
    let args = Arc::new(args);
    let allowed_statuses = Arc::new(args.get_status_codes());
    
    // Conteneurs partagés entre les tâches asynchrones
    let discovered_servers = Arc::new(Mutex::new(HashSet::new()));
    let findings = Arc::new(Mutex::new(Vec::<FuzzerFinding>::new())); // Pour stocker le JSON final

    let semaphore = Arc::new(Semaphore::new(args.threads));
    let mut tasks = vec![];

    for word in words {
        let mut payloads = vec![word.clone()];
        for ext in &extensions {
            payloads.push(format!("{}.{}", word, ext));
        }

        for payload in payloads {
            let client = Arc::clone(&client);
            let args = Arc::clone(&args);
            let allowed_statuses = Arc::clone(&allowed_statuses);
            let discovered_servers = Arc::clone(&discovered_servers);
            let findings = Arc::clone(&findings); // Référence vers la liste de résultats
            let permit = Arc::clone(&semaphore).acquire_owned().await?;

            let base_url = args.url.trim_end_matches('/');
            let target_url = format!("{}/{}", base_url, payload);
            let payload_clone = payload.clone();

            let task = tokio::spawn(async move {
                match client.get(&target_url).send().await {
                    Ok(response) => {
                        let status = response.status().as_u16();
                        if allowed_statuses.contains(&status) {
                            let server_header = response
                                .headers()
                                .get("server")
                                .and_then(|h| h.to_str().ok())
                                .unwrap_or("Inconnu")
                                .to_string();

                            println!(" -> /{} (Status: {}) [Server: {}]", payload_clone, status, server_header);

                            // Sauvegarde de la technologie unique
                            if let Ok(mut servers) = discovered_servers.lock() {
                                servers.insert(server_header.clone());
                            }

                            // Ajout du résultat dans notre vecteur pour le rapport JSON
                            if let Ok(mut findings_guard) = findings.lock() {
                                findings_guard.push(FuzzerFinding {
                                    path: format!("/{}", payload_clone),
                                    url: target_url,
                                    status,
                                    server: server_header,
                                });
                            }
                        }
                    }
                    Err(e) => {
                        if args.verbose {
                            println!("[!] Erreur sur : /{} -> {}", payload_clone, e);
                        }
                    }
                }
                drop(permit);
            });

            tasks.push(task);
        }
    }

    for task in tasks {
        let _ = task.await;
    }

    println!("[+] Fuzzing terminé.");

    // --- AFFICHAGE DE LA SYNTHÈSE FINALE ---
    println!("\n--- [ Technologies Web Découvertes ] ---");
    if let Ok(servers) = discovered_servers.lock() {
        for server in servers.iter() {
            println!(" • Le composant suivant a été détecté : {}", server);
        }
    }
    println!("----------------------------------------");

    // --- ENREGISTREMENT DU RAPPORT JSON ---
    if let Some(output_path) = &args.output {
        println!("[+] Écriture du rapport JSON dans : {:?}", output_path);
        if let Ok(findings_guard) = findings.lock() {
            // Création du fichier physique
            let file = File::create(output_path)?;
            // Sérialisation propre avec indentation (pretty-print)
            serde_json::to_writer_pretty(file, &*findings_guard)?;
            println!("[+] Rapport JSON généré avec succès ! ({} entrées)", findings_guard.len());
        }
    }

    Ok(())
}