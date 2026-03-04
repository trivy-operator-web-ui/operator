use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::kube_types::{Artifact, sbom_report::SbomReportSummary};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SimpleSbomReportDTO {
    pub artifact: Artifact,
    #[serde(rename = "ownersCount")]
    pub owners_count: usize,
    pub summary: SbomReportSummary,
    pub namespaces: HashSet<String>,
}

impl SimpleSbomReportDTO {
    pub fn new(
        artifact: Artifact,
        owners_count: usize,
        summary: SbomReportSummary,
        namespaces: HashSet<String>,
    ) -> SimpleSbomReportDTO {
        SimpleSbomReportDTO {
            artifact,
            owners_count,
            summary,
            namespaces,
        }
    }
}
