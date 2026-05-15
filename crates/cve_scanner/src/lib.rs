pub mod models;
pub mod data;
pub mod loader;

// Re-export les types principaux pour faciliter l'utilisation
pub use models::{Service, Vulnerability, ServiceList, ScanReport};
pub use loader::{load_services_from_file, load_services_from_json};
pub use data::get_cve_database;
