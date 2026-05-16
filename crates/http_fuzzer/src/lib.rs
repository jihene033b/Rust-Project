use clap::Parser;
use std::path::PathBuf;
use std::fs::File;
use std::io::{BufRead, BufReader};
use reqwest::Client;
use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use tokio::sync::Semaphore;

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

    /// Extensions de fichiers à tester (ex: php,txt,html)
    #[arg(short = 'x', long)]
    pub extensions: Option<String>,

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

    /// Analyse la chaîne des extensions pour renvoyer un vecteur propre (ex: ["php", "txt"])
    pub fn get_extensions(&self) -> Vec<String> {
        match &self.extensions {
            Some(exts) => exts
                .split(',')
                .map(|s| s.trim().trim_start_matches('.').to_string()) // Nettoie si l'utilisateur écrit ".php" au lieu de "php"
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
    
    // Récupération et nettoyage des extensions
    let extensions = args.get_extensions();
    
    // Calcul du nombre total de requêtes théoriques
    let total_requests = words.len() * (1 + extensions.len());
    println!("[+] {} mots chargés (Extensions configurées : {}). Total estimé : {} requêtes.", 
        words.len(), 
        if extensions.is_empty() { "Aucune".to_string() } else { args.extensions.clone().unwrap() },
        total_requests
    );
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
    let discovered_servers = Arc::new(Mutex::new(HashSet::new()));

    let semaphore = Arc::new(Semaphore::new(args.threads));
    let mut tasks = vec![];

    for word in words {
        // Pour chaque mot, on génère la liste des patterns à tester (le mot brut + le mot avec extensions)
        let mut payloads = vec![word.clone()];
        for ext in &extensions {
            payloads.push(format!("{}.{}", word, ext));
        }

        // On boucle sur tous les payloads générés pour ce mot précis
        for payload in payloads {
            let client = Arc::clone(&client);
            let args = Arc::clone(&args);
            let allowed_statuses = Arc::clone(&allowed_statuses);
            let discovered_servers = Arc::clone(&discovered_servers);
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

                            if let Ok(mut servers) = discovered_servers.lock() {
                                servers.insert(server_header);
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

    println!("\n--- [ Technologies Web Découvertes ] ---");
    if let Ok(servers) = discovered_servers.lock() {
        if servers.is_empty() {
            println!(" Aucun serveur distinct n'a pu être identifié.");
        } else {
            for server in servers.iter() {
                println!(" • Le composant suivant a été détecté : {}", server);
            }
        }
    }
    println!("----------------------------------------\n");

    Ok(())
}