mod sbom_report;
pub use sbom_report::*;

mod vulnerability_report;
pub use vulnerability_report::*;

mod error;

use crate::kube_types::sbom_report::ImageSbomReport;
use crate::kube_types::vulnerability_report::ImageVulnerabilityReport;
use crate::kube_state::SharedState;
use actix_web::{App, HttpServer};

pub async fn start_api(
    vulnerability_report_state: SharedState<ImageVulnerabilityReport>,
    sbom_report_state: SharedState<ImageSbomReport>,
) -> anyhow::Result<()> {
    let server = HttpServer::new(move || {
        App::new()
            .service(build_vulnerability_report_image_scope(
                vulnerability_report_state.clone(),
            ))
            .service(build_sbom_report_api_scope(sbom_report_state.clone()))
    })
    .bind(("0.0.0.0", 8080))?
    .shutdown_timeout(5);

    let _ = server.run().await;

    Ok(())
}
