use crate::kubedata::{Summary, VulnerabilityReport};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// DTO returned to the frontend
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct SimpleVulnerabilityReport {
    /// Uid of the Vulnerability Report resource
    pub uid: String,

    /// Image in the format <repository>:<tag>
    pub image: String,

    /// Namespace of the vulnerability report
    pub namespace: String,

    /// Summary is a summary of Vulnerability counts grouped by Severity.
    pub summary: Summary,
}

impl From<VulnerabilityReport> for SimpleVulnerabilityReport {
    fn from(v: VulnerabilityReport) -> Self {
        Self {
            uid: v.metadata.uid.unwrap_or_default(),
            image: format!(
                "{}:{}",
                v.report.artifact.repository.unwrap_or_default(),
                v.report.artifact.tag.unwrap_or_default()
            ),
            namespace: v.metadata.namespace.unwrap_or_default(),
            summary: v.report.summary,
        }
    }
}
