use std::result::Result::Ok;

mod dto;
mod kube_types;

mod controller;
use controller::{start_sbom_report_controller, start_vulnerability_report_controller};

mod api;
use api::start_api;

mod kube_state;
use kube_state::SharedState;

use crate::kube_types::{
    sbom_report::ImageSbomReport, vulnerability_report::ImageVulnerabilityReport,
};

use kube::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let vulnerability_report_state = SharedState::<ImageVulnerabilityReport>::default();
    let sbom_state = SharedState::<ImageSbomReport>::default();

    let vulnerability_report_controller_client = Client::try_default().await?;
    let sbom_report_controller_client = Client::try_default().await?;

    let vulnerability_report_controller = start_vulnerability_report_controller(
        vulnerability_report_state.clone(),
        vulnerability_report_controller_client,
    );

    let sbom_report_controller =
        start_sbom_report_controller(sbom_state.clone(), sbom_report_controller_client);

    let api = start_api(vulnerability_report_state.clone(), sbom_state.clone());

    tokio::join!(vulnerability_report_controller, sbom_report_controller, api).2?;

    Ok(())
}
