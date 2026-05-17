use cve_scanner::{
    load_services_from_file, scan_services, filter_by_severity, filter_by_cvss_score,
    format_json, save_json_file,
    NvdClient, CveCache, Config,
};
use std::io::Write;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    // Parse la configuration CLI
    let config = match Config::from_args(args) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("❌ Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    println!("🚀 CVE Scanner v0.1.0\n");
    println!("📂 Input:       {:?}", config.input_file);
    println!("💾 Cache:       {:?}", config.cache_dir);
    println!("🔗 Use NVD API: {}", config.use_nvd);
    
    // Charger les services depuis le fichier JSON
    println!("\n📦 Loading services...");
    let services = match load_services_from_file(config.input_file.to_str().unwrap()) {
        Ok(svc) => {
            println!("✓ Loaded {} services", svc.len());
            svc
        }
        Err(e) => {
            eprintln!("❌ Failed to load services: {}", e);
            std::process::exit(1);
        }
    };

    // Scanner les services (logique Phase 1-2)
    println!("\n🔍 Scanning services...");
    let mut report = scan_services(services);
    println!("✓ Found {} vulnerabilities", report.vulnerabilities_found.len());

    // Enrichir avec l'API NVD si demandé
    if config.use_nvd {
        println!("\n🌐 Enriching with NVD API...");
        enrich_with_nvd(&mut report, &config).await;
    }

    // Filtrer les résultats
    if let Some(min_severity) = &config.min_severity {
        println!("\n🎯 Filtering by severity: {}", min_severity);
        let filtered = filter_by_severity(&report, min_severity);
        println!("✓ {} vulnerabilities match filter", filtered.len());
    }

    if let Some(min_cvss) = config.min_cvss_score {
        println!("\n📊 Filtering by CVSS score >= {}", min_cvss);
        let filtered = filter_by_cvss_score(&report, min_cvss);
        println!("✓ {} vulnerabilities match filter", filtered.len());
    }

    // Sauvegarder le rapport
    if let Some(output_file) = &config.output_file {
        println!("\n💾 Saving report to {:?}", output_file);
        match save_report(&report, output_file) {
            Ok(_) => println!("✓ Report saved"),
            Err(e) => {
                eprintln!("❌ Failed to save report: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Afficher le résumé
    println!("\n📊 Summary:");
    println!("  Total services: {}", report.scanned_services.len());
    println!("  Vulnerabilities found: {}", report.vulnerabilities_found.len());
    
    if !report.vulnerabilities_found.is_empty() {
        println!("\n🚨 Vulnerabilities:");
        for vuln in report.vulnerabilities_found.iter().take(10) {
            println!(
                "  - {} [{}] {} (CVSS: {:.1})",
                vuln.cve_id, vuln.severity, vuln.service_name, vuln.cvss_score
            );
        }
        if report.vulnerabilities_found.len() > 10 {
            println!("  ... and {} more", report.vulnerabilities_found.len() - 10);
        }
    }

    println!("\n✅ Scan completed!");
}

/// Enrichit le rapport avec les données de l'API NVD
async fn enrich_with_nvd(report: &mut cve_scanner::ScanReport, config: &Config) {
    let client = NvdClient::new();
    let cache = match CveCache::new(config.cache_dir.to_str().unwrap()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⚠️  Cache error (continuing without cache): {}", e);
            return;
        }
    };

    // Clone la liste pour éviter les problèmes de borrow
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
                // Sauvegarder dans le cache
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
fn save_report(report: &cve_scanner::ScanReport, path: &std::path::PathBuf) -> anyhow::Result<()> {
    let json = format_json(report)?;
    save_json_file(path.to_str().unwrap(), &json)?;
    Ok(())
}
