use k8s_openapi::{Metadata, NamespaceResourceScope, Resource};
use kube::api::ObjectMeta;
use serde::{Deserialize, Serialize};

use crate::kube_types::{Artifact, Registry, Scanner, Severity};

// https://github.com/kube-rs/kube/discussions/1762
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
#[serde(rename_all = "camelCase")]
pub struct ExposedSecretReport {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub report: ImageExposedSecretReport,
    pub metadata: ObjectMeta,
}

impl Resource for ExposedSecretReport {
    const API_VERSION: &'static str = "aquasecurity.github.io/v1alpha1";
    const GROUP: &'static str = "aquasecurity.github.io";
    const VERSION: &'static str = "v1alpha1";
    const KIND: &'static str = "ExposedSecretReport";
    const URL_PATH_SEGMENT: &'static str = "exposedsecretreports";
    type Scope = NamespaceResourceScope;
}

impl Metadata for ExposedSecretReport {
    type Ty = ObjectMeta;
    fn metadata(&self) -> &Self::Ty {
        &self.metadata
    }
    fn metadata_mut(&mut self) -> &mut Self::Ty {
        &mut self.metadata
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ImageExposedSecretReport {
    pub artifact: Artifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<Registry>,
    pub scanner: Scanner,
    pub secrets: Vec<ExposedSecret>,
    pub summary: ExposedSecretSummary,
    #[serde(rename = "updateTimestamp")]
    pub update_timestamp: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ExposedSecret {
    pub category: String,
    #[serde(rename = "match")]
    pub r#match: String,
    #[serde(rename = "ruleID")]
    pub rule_id: String,
    pub severity: Severity,
    pub target: String,
    pub title: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ExposedSecretSummary {
    #[serde(rename = "criticalCount")]
    pub critical_count: i64,
    #[serde(rename = "highCount")]
    pub high_count: i64,
    #[serde(rename = "lowCount")]
    pub low_count: i64,
    #[serde(rename = "mediumCount")]
    pub medium_count: i64,
}
