use crate::models::Vulnerability;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdCveResponse { pub result: Option<NvdResult> }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NvdResult {
    #[serde(rename = "CVE_Items")]
    pub cve_items: Option<Vec<CveItem>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CveItem { pub cve: CveData, pub impact: Option<Impact> }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CveData {
    #[serde(rename = "ID")] pub id: String,
    pub description: Option<DescriptionData>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DescriptionData {
    pub description_data: Option<Vec<DescriptionItem>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DescriptionItem { pub value: String }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Impact {
    #[serde(rename = "baseMetricV3")] pub base_metric_v3: Option<BaseMetricV3>,
    #[serde(rename = "baseMetricV2")] pub base_metric_v2: Option<BaseMetricV2>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BaseMetricV3 { #[serde(rename = "cvssV3")] pub cvss_v3: Option<CvssV3> }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CvssV3 {
    #[serde(rename = "baseSeverity")] pub base_severity: Option<String>,
    #[serde(rename = "baseScore")] pub base_score: f32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BaseMetricV2 { #[serde(rename = "cvssV2")] pub cvss_v2: Option<CvssV2> }

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CvssV2 { #[serde(rename = "baseScore")] pub base_score: f32 }

pub struct NvdClient { client: reqwest::Client }

impl NvdClient {
    pub fn new() -> Self { Self { client: reqwest::Client::new() } }

    pub async fn fetch_cve_details(&self, cve_id: &str) -> Result<Option<(String, f32)>> {
        let url = format!("https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={}", cve_id);
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;

        let response = self.client.get(&url).send().await.context(format!("Failed to fetch from NVD: {}", cve_id))?;
        if !response.status().is_success() { anyhow::bail!("NVD API error : {}", cve_id); }

        let nvd_response: NvdCveResponse = response.json().await.context("Failed to parse NVD response")?;

        if let Some(result) = nvd_response.result {
            if let Some(items) = result.cve_items {
                if let Some(item) = items.first() {
                    let description = item.cve.description.as_ref()
                        .and_then(|d| d.description_data.as_ref())
                        .and_then(|dd| dd.first())
                        .map(|di| di.value.clone())
                        .unwrap_or_else(|| "No description available".to_string());

                    let score = item.impact.as_ref().and_then(|i| i.base_metric_v3.as_ref()).and_then(|b| b.cvss_v3.as_ref()).map(|c| c.base_score)
                        .or_else(|| item.impact.as_ref().and_then(|i| i.base_metric_v2.as_ref()).and_then(|b| b.cvss_v2.as_ref()).map(|c| c.base_score))
                        .unwrap_or(0.0);

                    return Ok(Some((description, score)));
                }
            }
        }
        Ok(None)
    }

    pub async fn enrich_vulnerability(&self, vuln: &mut Vulnerability) -> Result<()> {
        if let Ok(Some((description, score))) = self.fetch_cve_details(&vuln.cve_id).await {
            vuln.description = description;
            vuln.cvss_score = score;
        }
        Ok(())
    }
}