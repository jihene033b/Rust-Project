// pub fn add(left: u64, right: u64) -> u64 {
//     left + right
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(name = "gobuster-rs")]
#[command(author = "Quentin GUILLAUME <ton_email@exemple.com>")]
#[command(version = "0.1.0")]
#[command(about = "Un fuzzer HTTP asynchrone ultra-rapide écrit en Rust", long_about = None)]
pub struct FuzzerArgs {
    /// URL cible à fuzzer (ex: http://192.168.1.64)
    #[arg(short, long, required = true)]
    pub url: String,

    /// Chemin vers la wordlist (ex: data/wordlists/common.txt)
    #[arg(short, long, required = true)]
    pub wordlist: PathBuf,

    /// Nombre de tâches asynchrones simultanées (threads virtuels)
    #[arg(short, long, default_value_t = 40)]
    pub threads: usize,

    /// Codes de statut HTTP à afficher (séparés par des virgules)
    #[arg(short, long, default_value = "200,204,301,302,307,401,403")]
    pub status_codes: String,

    /// Custom User-Agent pour contourner certaines protections WAF
    #[arg(short = 'a', long, default_value = "Mozilla/5.0 (Gobuster-RS)")]
    pub user_agent: String,

    /// Mode verbeux (affiche les requêtes en cours ou les erreurs)
    #[arg(short, long)]
    pub verbose: bool,
}

impl FuzzerArgs {
    /// Permet de parser directement les arguments depuis la ligne de commande
    pub fn parse_cli() -> Self {
        Self::parse()
    }

    /// Fonction utilitaire pour transformer la chaîne "200,301" en un vecteur d'entiers [200, 301]
    pub fn get_status_codes(&self) -> Vec<u16> {
        self.status_codes
            .split(',')
            .filter_map(|s| s.trim().parse::<u16>().ok())
            .collect()
        }
}

use std::fs::File;
use std::io::{BufRead, BufReader};
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Fonction pour charger la wordlist en mémoire
pub fn read_wordlist(path: &std::path::Path) -> Result<Vec<String>, std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    
    // On lit chaque ligne, on enlève les espaces/retours à la ligne, et on filtre les lignes vides
    let words = reader
        .lines()
        .filter_map(|line| line.ok())
        .map(|w| w.trim().to_string())
        .filter(|w| !w.is_empty())
        .collect();
        
    Ok(words)
}

/// Moteur principal du fuzzer asynchrone
pub async fn run_fuzzer(args: FuzzerArgs) -> Result<(), anyhow::Error> {
    println!("[+] Chargement de la wordlist...");
    let words = read_wordlist(&args.wordlist)?;
    println!("[+] {} mots chargés. Initialisation du scan...", words.len());

    // AJOUTE CETTE LIGNE POUR LE TIMEOUT
    let timeout_duration = std::time::Duration::from_secs(5);

    // 1. Création du client HTTP Reqwest avec le User-Agent personnalisé et un Timeout
    let client = Client::builder()
        .user_agent(&args.user_agent)
        .timeout(timeout_duration) // <-- ICI : Sécurité pour éviter le freeze
        .redirect(reqwest::redirect::Policy::none()) // <-- AJOUTE CETTE LIGNE ICI
        .build()?;

    // On enveloppe le client et les arguments dans un Arc (Atomic Reference Counted) 
    // pour pouvoir les partager en toute sécurité entre les tâches asynchrones
    let client = Arc::new(client);
    let args = Arc::new(args);
    let allowed_statuses = Arc::new(args.get_status_codes());

    // 2. Utilisation d'un sémaphore pour limiter le nombre de requêtes simultanées (le multi-threading)
    let semaphore = Arc::new(Semaphore::new(args.threads));
    let mut tasks = vec![];

    for word in words {
        let client = Arc::clone(&client);
        let args = Arc::clone(&args);
        let allowed_statuses = Arc::clone(&allowed_statuses);
        let permit = Arc::clone(&semaphore).acquire_owned().await?;

        // On construit l'URL finale (ex: http://example.com/admin)
        let base_url = args.url.trim_end_matches('/');
        let target_url = format!("{}/{}", base_url, word);

        // On lance la requête de manière totalement asynchrone via Tokio
        let task = tokio::spawn(async move {
            // Le "permit" est conservé pendant la requête, limitant le flux global
            match client.get(&target_url).send().await {
                Ok(response) => {
                    let status = response.status().as_u16();
                    // Si le code de statut fait partie de la liste surveillée, on l'affiche
                    if allowed_statuses.contains(&status) {
                        println!(" -> /{} (Status: {})", word, status);
                    }
                }
                Err(_) => {
                    if args.verbose {
                        println!("[!] Erreur de connexion sur : /{}", word);
                    }
                }
            }
            drop(permit); // On libère la place pour le mot suivant
        });

        tasks.push(task);
    }

    // On attend que toutes les requêtes soient terminées
    for task in tasks {
        let _ = task.await;
    }

    println!("[+] Fuzzing terminé.");
    Ok(())
}