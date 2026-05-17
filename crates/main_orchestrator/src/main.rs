use std::io::Write;

use anyhow::Result;
use clap::{Parser, Subcommand};
use http_fuzzer::{FuzzerArgs, run_fuzzer};
use network_scanner::{PortInfo, ScanConfig, TOP_1000_PORTS, parse_ports, parse_targets, scan};
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(name = "scanner", about = "Security tooling suite")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Fuzz {
        #[command(flatten)]
        args: FuzzerArgs,
    },

    Scan {
        #[arg(short, long)]
        target: String,

        #[arg(short, long)]
        ports: Option<String>,

        #[arg(long)]
        top_ports: Option<usize>,

        #[arg(short = 'T', long, default_value = "3", value_parser = clap::value_parser!(u8).range(0..=5))]
        timing: u8,

        #[arg(long = "no-ping")]
        no_ping: bool,
    },
}

fn timing_config(level: u8) -> (usize, u64) {
    match level {
        0 => (1, 5000),
        1 => (10, 3000),
        2 => (50, 2000),
        3 => (1000, 1000),
        4 => (3000, 500),
        5 => (5000, 200),
        _ => (1000, 1000),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        // ######## FONCTION MAIN POUR TESTER LE FUZZER ############
        Commands::Fuzz { args } => {
            // 1. Affichage de la configuration (super propre pour le feedback utilisateur)
            println!("--- [ Configuration du Fuzzer ] ---");
            println!("Cible : {}", args.url);
            println!("Wordlist : {:?}", args.wordlist);
            println!("Threads : {}", args.threads);
            println!("User-Agent : {}", args.user_agent);
            println!("Codes HTTP surveillés : {:?}", args.get_status_codes());
            println!("-----------------------------------\n");

            // 2. Lancement du moteur de fuzzing asynchrone
            run_fuzzer(args).await?;
        }

        Commands::Scan {
            target,
            ports,
            top_ports,
            timing,
            no_ping,
        } => {
            if timing >= 4 {
                println!(
                    "  T{} est {} et peut surcharger le réseau ou déclencher des alertes IDS.",
                    timing,
                    if timing == 5 { "INSANE" } else { "AGRESSIF" }
                );
                print!("Continuer ? [y/N] : ");
                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Annulé.");
                    return Ok(());
                }
            }

            let port_list: Vec<u16> = if let Some(p) = ports {
                parse_ports(&p)?
            } else if let Some(n) = top_ports {
                TOP_1000_PORTS.iter().take(n).copied().collect()
            } else {
                TOP_1000_PORTS.to_vec()
            };

            let (concurrency, timeout_ms) = timing_config(timing);
            let targets = parse_targets(&target)?;
            let total = targets.len();

            println!("--- [ Network Scanner ] ---");
            println!("Target  : {}", target);
            println!("Hosts   : {}", total);
            println!("Ports   : {}", port_list.len());
            println!("Timing  : T{}", timing);
            println!("Threads : {}", concurrency);
            println!("Timeout : {}ms", timeout_ms);
            println!("---------------------------\n");

            let config = ScanConfig {
                concurrency,
                timeout_ms,
                skip_ping: no_ping,
                ports: port_list,
            };

            let (tx, mut rx) = mpsc::channel::<(String, PortInfo)>(256);

            // Affichage en-tête tableau
            println!(
                "{:<10} {:<10} {:<16} {}",
                "PORT", "STATE", "SERVICE", "BANNER"
            );
            println!("{}", "-".repeat(70));

            let printer = tokio::spawn(async move {
                while let Some((_ip, info)) = rx.recv().await {
                    let banner = info.banner.as_deref().unwrap_or("");
                    println!(
                        "{:<10} {:<10} {:<16} {}",
                        format!("{}/tcp", info.port),
                        info.state.to_string(),
                        info.service,
                        banner
                    );
                }
            });

            let results = scan(targets, config, tx).await?;
            printer.await?;

            println!("\n--- [ Résumé ] ---");
            for result in &results {
                println!(
                    "{} : {} open, {} closed, {} filtered",
                    result.ip,
                    result.open_ports.len(),
                    result.closed_count,
                    result.filtered_count,
                );
            }
        }
    }

    Ok(())
}
