use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::kube_types::{Artifact, exposed_secret_report::ExposedSecretSummary};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct SimpleExposedSecretReportDTO {
    pub artifact: Artifact,
    #[serde(rename = "ownersCount")]
    pub owners_count: usize,
    pub summary: ExposedSecretSummary,
    pub namespaces: HashSet<String>,
}

impl SimpleExposedSecretReportDTO {
    pub fn new(
        artifact: Artifact,
        owners_count: usize,
        summary: ExposedSecretSummary,
        namespaces: HashSet<String>,
    ) -> SimpleExposedSecretReportDTO {
        SimpleExposedSecretReportDTO {
            artifact,
            owners_count,
            summary,
            namespaces,
        }
    }
}
