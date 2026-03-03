use std::result::Result::Ok;

mod dto;
mod kube_types;

mod controller;
use controller::start::start_controller;

mod api;
use api::start_api;

mod kube_state;
use kube_state::SharedState;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};

use crate::kube_types::{
    sbom_report::ImageSbomReport, vulnerability_report::ImageVulnerabilityReport,
};

use kube::Client;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let vulnerability_reports_state = SharedState::<ImageVulnerabilityReport>::default();
    let sbom_reports_state = SharedState::<ImageSbomReport>::default();

    let logger = tracing_subscriber::fmt::layer().compact();
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("error"))
        .unwrap();

    Registry::default().with(env_filter).with(logger).init();

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
