pub mod models;
pub mod data;
pub mod loader;
pub mod scanner;
pub mod nvd_client;
pub mod cache;
pub mod cli;
pub mod utils;
pub mod consolidator; // Expose le consolidateur 🚀

pub use models::{Service, Vulnerability, ServiceList, ScanReport};
pub use loader::{load_services_from_file, load_services_from_json};
pub use data::get_cve_database;
pub use scanner::{scan_services, count_by_severity, filter_by_severity, filter_by_cvss_score};
pub use nvd_client::NvdClient;
pub use cache::CveCache;
pub use cli::Config;
pub use utils::{format_json, find_files_by_pattern, save_json_file};
pub use consolidator::generate_all_services_json; // Facilite l'import