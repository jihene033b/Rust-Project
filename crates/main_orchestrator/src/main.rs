use cve_scanner::{
    load_services_from_file, scan_services, filter_by_severity, filter_by_cvss_score,
    format_json, save_json_file, find_files_by_pattern,
    NvdClient, CveCache,
};
use std::io::Write;
use std::fs;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_help();
        return;
    }

    match args[1].as_str() {
        "scan" => {
            let scanner_args: Vec<String> = vec![args[0].clone()]
                .into_iter()
                .chain(args[2..].to_vec())
                .collect();
            
            run_scanner(scanner_args).await;
        }
        "--help" | "-h" => print_help(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_help();
        }
    }
}

fn print_help() {
    println!("🔒 Security Scan Orchestrator");
    println!("\nUsage:");
    println!("  cargo run -- scan <input_dir> --output <report_dir> [OPTIONS]");
    println!("\nOptions:");
    println!("  --pattern <regex>       Pattern to find scan files (default: net_scanner\\.json|scan_report\\.json)");
    println!("  --cache <dir>           Cache directory (default: ./cache)");
    println!("  --nvd                   Use NVD API for enrichment");
    println!("  --min-severity LEVEL    Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)");
    println!("  --min-cvss SCORE        Filter by CVSS score");
    println!("\nExample:");
    println!("  cargo run -- scan crates/cve_scanner/results/scans --output crates/cve_scanner/results/reports --nvd");
    println!("\nExpected input files:");
    println!("  - net_scanner.json (from network scanner)");
    println!("  - scan_report.json (from HTTP fuzzer)");
}

async fn run_scanner(args: Vec<String>) {
    if args.len() < 2 {
        eprintln!("❌ Missing arguments");
        print_help();
        std::process::exit(1);
    }

    let input_path = &args[1];
    let mut output_dir = None;
    let mut pattern = "(net_scanner|scan_report)\\.json$".to_string();
    let mut cache_dir = "cache".to_string();
    let mut use_nvd = false;
    let mut min_severity = None;
    let mut min_cvss_score = None;

    // Parse les options
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--output" => {
                if i + 1 < args.len() {
                    output_dir = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    eprintln!("--output requires a directory path");
                    std::process::exit(1);
                }
            }
            "--pattern" => {
                if i + 1 < args.len() {
                    pattern = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("--pattern requires a regex");
                    std::process::exit(1);
                }
            }
            "--cache" => {
                if i + 1 < args.len() {
                    cache_dir = args[i + 1].clone();
                    i += 2;
                } else {
                    eprintln!("--cache requires a directory path");
                    std::process::exit(1);
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
                    eprintln!("--min-severity requires a level");
                    std::process::exit(1);
                }
            }
            "--min-cvss" => {
                if i + 1 < args.len() {
                    if let Ok(score) = args[i + 1].parse::<f32>() {
                        min_cvss_score = Some(score);
                    } else {
                        eprintln!("Invalid CVSS score");
                        std::process::exit(1);
                    }
                    i += 2;
                } else {
                    eprintln!("--min-cvss requires a number");
                    std::process::exit(1);
                }
            }
            _ => {
                eprintln!("Unknown option: {}", args[i]);
                i += 1;
            }
        }
    }

    // Créer le dossier cache s'il n'existe pas
    let _ = fs::create_dir_all(&cache_dir);

    println!("🚀 CVE Scanner v0.1.0\n");
    println!("📂 Input directory: {}", input_path);
    println!("📤 Output directory: {}", output_dir.as_ref().unwrap_or(&"(none)".to_string()));
    println!("🔍 Pattern: {}", pattern);
    println!("💾 Cache: {}", cache_dir);
    println!("🔗 Use NVD API: {}\n", use_nvd);

    // Trouver tous les fichiers JSON correspondant au pattern
    println!("🔎 Discovering scan files with pattern: {}\n", pattern);
    let scan_files = match find_files_by_pattern(input_path, &pattern) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("❌ Failed to discover files: {}", e);
            std::process::exit(1);
        }
    };

    if scan_files.is_empty() {
        println!("⚠️  No files found matching pattern '{}' in '{}'", pattern, input_path);
        return;
    }

    println!("✓ Found {} scan file(s)\n", scan_files.len());

    // Traiter chaque fichier
    for (index, filename) in scan_files.iter().enumerate() {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("[{}/{}] Processing: {}", index + 1, scan_files.len(), filename);
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

        let input_file = format!("{}/{}", input_path, filename);
        
        // Charger les services
        println!("📦 Loading services...");
        let services = match load_services_from_file(&input_file) {
            Ok(svc) => {
                println!("✓ Loaded {} services\n", svc.len());
                svc
            }
            Err(e) => {
                eprintln!("❌ Failed to load {}: {}\n", filename, e);
                continue;
            }
        };

        // Scanner les services
        println!("🔍 Scanning services...");
        let mut report = scan_services(services);
        println!("✓ Found {} vulnerabilities\n", report.vulnerabilities_found.len());

        // Enrichir avec l'API NVD si demandé
        if use_nvd {
            println!("🌐 Enriching with NVD API...");
            enrich_with_nvd(&mut report, &cache_dir).await;
            println!();
        }

        // Filtrer les résultats
        if let Some(ref severity) = min_severity {
            println!("🎯 Filtering by severity: {}", severity);
            let filtered = filter_by_severity(&report, severity);
            println!("✓ {} vulnerabilities match filter\n", filtered.len());
        }

        if let Some(cvss) = min_cvss_score {
            println!("📊 Filtering by CVSS score >= {}", cvss);
            let filtered = filter_by_cvss_score(&report, cvss);
            println!("✓ {} vulnerabilities match filter\n", filtered.len());
        }

        // Sauvegarder le rapport
        if let Some(ref out_dir) = output_dir {
            let _ = fs::create_dir_all(out_dir);
            
            // Générer un nom de rapport unique
            let report_name = filename.replace(".json", "_report.json");
            let output_file = format!("{}/{}", out_dir, report_name);
            
            println!("💾 Saving report to: {}", output_file);
            match save_report(&report, &output_file) {
                Ok(_) => println!("✓ Report saved\n"),
                Err(e) => {
                    eprintln!("❌ Failed to save report: {}\n", e);
                    continue;
                }
            }
        }

        // Afficher le résumé
        println!("📊 Summary:");
        println!("  Total services: {}", report.scanned_services.len());
        println!("  Vulnerabilities found: {}", report.vulnerabilities_found.len());
        
        if !report.vulnerabilities_found.is_empty() {
            println!("\n🚨 Top Vulnerabilities:");
            for vuln in report.vulnerabilities_found.iter().take(5) {
                println!(
                    "  - {} [{}] {} (CVSS: {:.1})",
                    vuln.cve_id, vuln.severity, vuln.service_name, vuln.cvss_score
                );
            }
            if report.vulnerabilities_found.len() > 5 {
                println!("  ... and {} more", report.vulnerabilities_found.len() - 5);
            }
        }

        println!();
    }

    println!("✅ All scans completed!");
}

/// Enrichit le rapport avec les données de l'API NVD
async fn enrich_with_nvd(report: &mut cve_scanner::ScanReport, cache_dir: &str) {
    let client = NvdClient::new();
    let cache = match CveCache::new(cache_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⚠️  Cache error (continuing without cache): {}", e);
            return;
        }
    };

    let vuln_count = report.vulnerabilities_found.len();
    
    for index in 0..vuln_count {
        let cve_id = report.vulnerabilities_found[index].cve_id.clone();
        print!("  [{}/{}] Enriching {}... ", index + 1, vuln_count, cve_id);
        std::io::stdout().flush().ok();

        // Essayer le cache d'abord
        if let Ok(Some(cached)) = cache.get(&cve_id) {
            report.vulnerabilities_found[index].description = cached.description;
            report.vulnerabilities_found[index].cvss_score = cached.cvss_score;
            println!("(cached)");
            continue;
        }

        // Sinon, interroger l'API NVD
        match client.enrich_vulnerability(&mut report.vulnerabilities_found[index]).await {
            Ok(_) => {
                let _ = cache.set(
                    &cve_id,
                    report.vulnerabilities_found[index].description.clone(),
                    report.vulnerabilities_found[index].cvss_score,
                );
                println!("(from API)");
            }
            Err(e) => {
                println!("(error: {})", e);
            }
        }
    }
}

/// Sauvegarde le rapport en JSON formaté
fn save_report(report: &cve_scanner::ScanReport, path: &str) -> anyhow::Result<()> {
    let json = format_json(report)?;
    save_json_file(path, &json)?;
    Ok(())
}
