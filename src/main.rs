use std::result::Result::Ok;

mod dto;
mod kube_types;

mod controller;
use controller::start::start_controller;

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
    let vulnerability_reports_state = SharedState::<ImageVulnerabilityReport>::default();
    let sbom_reports_state = SharedState::<ImageSbomReport>::default();

    let client = Client::try_default().await?;

    let controller = start_controller(
        client.clone(),
        vulnerability_reports_state.clone(),
        sbom_reports_state.clone(),
    );

    let api = start_api(
        vulnerability_reports_state.clone(),
        sbom_reports_state.clone(),
    );

    tokio::join!(api, controller).1?;

    Ok(())
}
