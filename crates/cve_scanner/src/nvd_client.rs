use crate::models::Vulnerability;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Structure pour parser la réponse de l'API NVD
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdCveResponse {
    pub result: Option<NvdResult>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdResult {
    #[serde(rename = "CVE_Items")]
    pub cve_items: Option<Vec<CveItem>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CveItem {
    pub cve: CveData,
    pub impact: Option<Impact>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CveData {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "description")]
    pub description: Option<DescriptionData>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DescriptionData {
    #[serde(rename = "description_data")]
    pub description_data: Option<Vec<DescriptionItem>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DescriptionItem {
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Impact {
    #[serde(rename = "baseMetricV3")]
    pub base_metric_v3: Option<BaseMetricV3>,
    #[serde(rename = "baseMetricV2")]
    pub base_metric_v2: Option<BaseMetricV2>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BaseMetricV3 {
    #[serde(rename = "cvssV3")]
    pub cvss_v3: Option<CvssV3>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CvssV3 {
    #[serde(rename = "baseSeverity")]
    pub base_severity: Option<String>,
    #[serde(rename = "baseScore")]
    pub base_score: f32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BaseMetricV2 {
    #[serde(rename = "cvssV2")]
    pub cvss_v2: Option<CvssV2>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CvssV2 {
    #[serde(rename = "baseScore")]
    pub base_score: f32,
}

/// Client HTTP pour interroger l'API NVD
pub struct NvdClient {
    client: reqwest::Client,
}

impl NvdClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Récupère les détails d'une CVE depuis l'API NVD
    /// API docs: https://services.nvd.nist.gov/rest/json/cves/1.0
    pub async fn fetch_cve_details(&self, cve_id: &str) -> Result<Option<(String, f32)>> {
        let url = format!(
            "https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={}",
            cve_id
        );

        // NOTE: Rate limiting! NVD API: ~5 req/sec max
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .context(format!("Failed to fetch from NVD: {}", cve_id))?;

        let status = response.status();
        if !status.is_success() {
            anyhow::bail!("NVD API returned {}: {}", status, cve_id);
        }

        let nvd_response: NvdCveResponse = response
            .json()
            .await
            .context("Failed to parse NVD response")?;

        // Extraire la description et le score CVSS
        if let Some(result) = nvd_response.result {
            if let Some(items) = result.cve_items {
                if let Some(item) = items.first() {
                    let description = item
                        .cve
                        .description
                        .as_ref()
                        .and_then(|d| d.description_data.as_ref())
                        .and_then(|dd| dd.first())
                        .map(|di| di.value.clone())
                        .unwrap_or_else(|| "No description available".to_string());

                    // Préférer CVSS v3, sinon v2
                    let score = item
                        .impact
                        .as_ref()
                        .and_then(|i| i.base_metric_v3.as_ref())
                        .and_then(|b| b.cvss_v3.as_ref())
                        .map(|c| c.base_score)
                        .or_else(|| {
                            item.impact
                                .as_ref()
                                .and_then(|i| i.base_metric_v2.as_ref())
                                .and_then(|b| b.cvss_v2.as_ref())
                                .map(|c| c.base_score)
                        })
                        .unwrap_or(0.0);

                    return Ok(Some((description, score)));
                }
            }
        }

        Ok(None)
    }

    /// Enrichit une vulnérabilité avec les données NVD
    pub async fn enrich_vulnerability(&self, vuln: &mut Vulnerability) -> Result<()> {
        if let Ok(Some((description, score))) = self.fetch_cve_details(&vuln.cve_id).await {
            vuln.description = description;
            vuln.cvss_score = score;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nvd_client_creation() {
        let client = NvdClient::new();
        // Just ensure it constructs without error
        assert_eq!(std::mem::size_of_val(&client.client) > 0, true);
    }

    #[tokio::test]
    #[ignore]  // À ignorer par défaut (fait des vraies requêtes HTTP)
    async fn test_fetch_cve_details_real() {
        let client = NvdClient::new();
        let result = client.fetch_cve_details("CVE-2021-41773").await;
        
        match result {
            Ok(Some((desc, score))) => {
                println!("Description: {}", desc);
                println!("Score: {}", score);
                assert!(!desc.is_empty());
                assert!(score >= 0.0);
            }
            Ok(None) => {
                println!("No data returned from NVD");
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}
