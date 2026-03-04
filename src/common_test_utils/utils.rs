use crate::kube_types::{SbomReport, VulnerabilityReport};
use anyhow::Result;
use std::fs;

pub static ETCD: &str = "etcd";
pub static RABBIT_ONE: &str = "rabbit-one";
pub static RABBIT_TWO: &str = "rabbit-two";

pub static RESOURCES: [&str; 2] = [ETCD, RABBIT_ONE];

#[warn(dead_code)]
pub static NAMESPACES: [&str; 3] = [ETCD, RABBIT_ONE, RABBIT_TWO];

pub static TEST_USERNAME: &str = "username";
pub static TEST_PASSWORD: &str = "username";

pub fn read_test_vulnerability_report(name: &str) -> Result<VulnerabilityReport> {
    let report: VulnerabilityReport = serde_yaml::from_str(&fs::read_to_string(format!(
        "test_assets/vulnerability_reports/{}.yaml",
        name
    ))?)?;

    Ok(report)
}

pub fn read_test_sbom_report(name: &str) -> Result<SbomReport> {
    let report: SbomReport = serde_yaml::from_str(&fs::read_to_string(format!(
        "test_assets/sbom_reports/{}.yaml",
        name
    ))?)?;

    Ok(report)
}
