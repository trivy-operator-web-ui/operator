use crate::kubedata::{Artifact, Summary, VulnerabilityReport};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// DTO returned to the frontend
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct SimpleVulnerabilityReport {
    /// Summary is a summary of Vulnerability counts grouped by Severity.
    pub summary: Summary,

    /// Name of the Vulnerability Report
    pub name: String,

    /// Artifact represents a standalone, executable package of software that includes everything needed to
    /// run an application.
    pub artifact: Artifact,

    pub uid: String,
}

impl From<VulnerabilityReport> for SimpleVulnerabilityReport {
    fn from(v: VulnerabilityReport) -> Self {
        Self {
            name: v.metadata.name.unwrap_or_default(),
            summary: v.report.summary,
            artifact: v.report.artifact,
            uid: v.metadata.uid.unwrap_or_default(),
        }
    }
}
