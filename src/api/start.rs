use crate::api::routes::{
    build_exposed_secret_report_api_service, build_health_api_service, build_login_service,
    build_sbom_report_api_service, build_vulnerability_report_image_service,
};
use crate::api::services::{
    CookieService, ExposedSecretReportService, JwtService, SbomReportService, UserService,
    VulnerabilityReportService,
};
use crate::kube_types::exposed_secret_report::ImageExposedSecretReport;
use crate::kube_types::sbom_report::ImageSbomReport;
use crate::kube_types::vulnerability_report::ImageVulnerabilityReport;
use crate::states::ReportState;
use actix_web::middleware::Logger;
use actix_web::web::Data;
use actix_web::{App, HttpServer};

pub async fn start_api(
    vulnerability_report_state: ReportState<ImageVulnerabilityReport>,
    sbom_report_state: ReportState<ImageSbomReport>,
    exposed_secret_report_state: ReportState<ImageExposedSecretReport>,
    username: String,
    password: String,
) -> anyhow::Result<()> {
    let user_service = UserService::new(username, password);
    let vulnerability_report_service = VulnerabilityReportService::new(vulnerability_report_state);
    let sbom_report_service = SbomReportService::new(sbom_report_state);
    let exposed_secret_report_service =
        ExposedSecretReportService::new(exposed_secret_report_state);

    let jwt_service = JwtService::new();
    let cookie_service = CookieService::new();

    let server = HttpServer::new(move || {
        App::new()
            .app_data(Data::new(jwt_service.clone()))
            .app_data(Data::new(cookie_service.clone()))
            .wrap(Logger::default())
            .service(build_vulnerability_report_image_service(
                vulnerability_report_service.clone(),
            ))
            .service(build_sbom_report_api_service(sbom_report_service.clone()))
            .service(build_exposed_secret_report_api_service(
                exposed_secret_report_service.clone(),
            ))
            .service(build_login_service(user_service.clone()))
            .service(build_health_api_service())
    })
    .workers(4)
    .bind(("0.0.0.0", 8080))?
    .shutdown_timeout(5);

    let _ = server.run().await;

    Ok(())
}
