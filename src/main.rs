use std::result::Result::Ok;

use tracing_subscriber::{EnvFilter, Registry, layer::SubscriberExt, util::SubscriberInitExt};
use trivy_operator_web_ui::{
    api::start_api,
    controller::start_controller,
    kube_types::{sbom_report::ImageSbomReport, vulnerability_report::ImageVulnerabilityReport},
    states::ReportState,
};

use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let vulnerability_reports_state = ReportState::<ImageVulnerabilityReport>::default();
    let sbom_reports_state = ReportState::<ImageSbomReport>::default();

    let username = env::var("USERNAME").expect("USERNAME environment variable must be set !");
    let password = env::var("PASSWORD").expect("PASSWORD environment variable must be set !");

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

    let controller = tokio::spawn(controller);
    let api = tokio::spawn(api);

    tokio::select! {
        res = controller => println!("controller exited: {:?}", res),
        res = api => println!("api exited: {:?}", res),
    }

    Ok(())
}
