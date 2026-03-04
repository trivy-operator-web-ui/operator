use std::result::Result::Ok;

mod kube_types;

mod controller;
use controller::start_controller;

mod api;
use api::start_api;

mod states;

use states::ReportState;
use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};

use crate::kube_types::{
    sbom_report::ImageSbomReport, vulnerability_report::ImageVulnerabilityReport,
};

use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let vulnerability_reports_state = ReportState::<ImageVulnerabilityReport>::default();
    let sbom_reports_state = ReportState::<ImageSbomReport>::default();

    let username =
        env::var("PORTAL_USERNAME").expect("PORTAL_USERNAME environment variable must be set !");
    let password =
        env::var("PORTAL_PASSWORD").expect("PORTAL_PASSWORD environment variable must be set !");

    let logger = tracing_subscriber::fmt::layer().compact();
    let env_filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("error"))
        .unwrap();

    Registry::default().with(env_filter).with(logger).init();

    let controller = start_controller(
        vulnerability_reports_state.clone(),
        sbom_reports_state.clone(),
    );

    let api = start_api(
        vulnerability_reports_state.clone(),
        sbom_reports_state.clone(),
        username,
        password,
    );

    tokio::join!(api, controller).1?;

    Ok(())
}

#[cfg(test)]
mod common_test_utils;
