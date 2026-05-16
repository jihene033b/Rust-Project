
use clap::Parser;
use std::path::PathBuf;
use std::fs::File;
use std::io::{BufRead, BufReader};
use reqwest::Client;
use std::sync::{Arc, Mutex}; // Ajout de Mutex ici
use std::collections::HashSet; // Ajout de HashSet pour l'unicité
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
    println!("[+] {} mots chargés. Initialisation du scan...", words.len());

    let timeout_duration = std::time::Duration::from_secs(5);

    let client = Client::builder()
        .user_agent(&args.user_agent)
        .timeout(timeout_duration)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let client = Arc::new(client);
    let args = Arc::new(args);
    let allowed_statuses = Arc::new(args.get_status_codes());

    // Initialisation du HashSet sécurisé pour stocker les serveurs uniques
    let discovered_servers = Arc::new(Mutex::new(HashSet::new()));

    let semaphore = Arc::new(Semaphore::new(args.threads));
    let mut tasks = vec![];

    for word in words {
        let client = Arc::clone(&client);
        let args = Arc::clone(&args);
        let allowed_statuses = Arc::clone(&allowed_statuses);
        let permit = Arc::clone(&semaphore).acquire_owned().await?;
        
        // On clone la référence du HashSet pour l'envoyer dans la tâche
        let discovered_servers = Arc::clone(&discovered_servers);

        let base_url = args.url.trim_end_matches('/');
        let target_url = format!("{}/{}", base_url, word);

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

                        println!(" -> /{} (Status: {}) [Server: {}]", word, status, server_header);

                        // On verrouille le Mutex pour insérer le serveur trouvé en toute sécurité
                        if let Ok(mut servers) = discovered_servers.lock() {
                            servers.insert(server_header);
                        }
                    }
                }
                Err(e) => {
                    if args.verbose {
                        println!("[!] Erreur sur : /{} -> {}", word, e);
                    }
                }
            }
            drop(permit);
        });

        tasks.push(task);
    }

    for task in tasks {
        let _ = task.await;
    }

    println!("[+] Fuzzing terminé.");

    // --- AFFICHAGE DE LA SYNTHÈSE FINALE ---
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