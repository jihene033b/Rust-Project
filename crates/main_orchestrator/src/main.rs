// fn main() {
//     println!("Hello, world!");
// }
// On importe la structure que tu viens de créer dans ta crate http_fuzzer
use http_fuzzer::{FuzzerArgs, run_fuzzer};

#[tokio::main] // Obligatoire pour exécuter du code asynchrone avec Tokio
async fn main() -> Result<(), anyhow::Error> {
    // 1. Analyse les arguments passés au terminal
    let args = FuzzerArgs::parse_cli();

    // 2. Affichage de la configuration (super propre pour le feedback utilisateur)
    println!("--- [ Configuration du Fuzzer ] ---");
    println!("Cible : {}", args.url);
    println!("Wordlist : {:?}", args.wordlist);
    println!("Threads : {}", args.threads);
    println!("User-Agent : {}", args.user_agent);
    println!("Codes HTTP surveillés : {:?}", args.get_status_codes());
    println!("-----------------------------------\n");

    // 3. Lancement du moteur de fuzzing asynchrone
    run_fuzzer(args).await?;
    
    Ok(())
}