use crate::{
    api::{
        error::ZipSbomError,
        middleware::authentication, services::SbomReportService,
    },
    kube_types::{Artifact},
};

use actix_web::{
    HttpResponse, Responder,
    dev::HttpServiceFactory,
    get,
    http::header::{DispositionParam, DispositionType},
    middleware::from_fn,
    post,
    web::{Data, Json, scope},
};

use chrono::Local;

use actix_web::http::header::ContentDisposition;

pub fn build_sbom_report_api_service(
    sbom_report_service: SbomReportService,
) -> impl HttpServiceFactory {
    scope("/api/sbom-reports")
        .app_data(Data::new(sbom_report_service))
        .service(simple_sbom_reports)
        .service(download_sbom_archive)
        .wrap(from_fn(authentication))
}

#[get("")]
pub async fn simple_sbom_reports(sbom_report_service: Data<SbomReportService>) -> impl Responder {
    let simple_sbom_reports = sbom_report_service.get_simple_sbom_reports();
    HttpResponse::Ok().json(&simple_sbom_reports)
}

#[post("/download")]
pub async fn download_sbom_archive(
    sbom_report_service: Data<SbomReportService>,
    artifacts: Json<Vec<Artifact>>,
) -> Result<HttpResponse, ZipSbomError> {

    let zip_result = sbom_report_service.zip_sboms_by_artifacts(artifacts.clone());

    match zip_result {
        Ok(zip) => {
            let zip_date = Local::now().format("%Y_%m_%d_%Hh%M").to_string();
            let zip_filename = format!("sbom_{zip_date}.zip");

            Ok(HttpResponse::Ok()
                .content_type("application/zip")
                .append_header(ContentDisposition {
                    disposition: DispositionType::Attachment,
                    parameters: vec![DispositionParam::Filename(zip_filename)],
                })
                .body(zip))
        },
        Err(err) => Err(err)
    }    
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs};

    use actix_web::{
        App, test::{self}
    };
    use anyhow::Result;
    use test::{TestRequest, init_service};

    use crate::{
        api::{
            dto::{SimpleSbomReportDTO},
            routes::build_sbom_report_api_service, services::SbomReportService,
        },
        kube_types::{SbomReport, Workload, sbom_report::ImageSbomReport},
        states::ReportState,
    };

    static TEST_RESOURCES: [&str; 2] = ["etcd", "rabbit-one"];

    fn read_test_resource(name: &str) -> Result<SbomReport> {
        let report: SbomReport = serde_yaml::from_str(&fs::read_to_string(format!(
            "test_assets/sbom_reports/{}.yaml",
            name
        ))?)?;

        Ok(report)
    }

    fn init_sbom_report_service() -> SbomReportService {
        let state = ReportState::<ImageSbomReport>::default();

        let mut reports = state.reports.lock().unwrap();
        let mut owners = state.owners.lock().unwrap();

        for rsc in TEST_RESOURCES {
            let vulnerability_report = read_test_resource(rsc).unwrap();

            let artifact = vulnerability_report.report.artifact.clone();
            reports.insert(artifact.clone(), vulnerability_report.report);

            let labels = vulnerability_report.metadata.labels.unwrap();
            let workload = Workload::new(labels);
            owners.insert(artifact, HashSet::from([workload]));
        }

        SbomReportService::new(state.clone())
    }

    fn get_api_snapshot(name: &str) -> Result<Vec<SimpleSbomReportDTO>> {
        let snapshot: Vec<SimpleSbomReportDTO> = serde_yaml::from_str(&fs::read_to_string(
            format!("test_assets/api_snapshots/sbom_reports/{}.json", name),
        )?)?;

        Ok(snapshot)
    }

    #[actix_web::test]
    async fn get_simple_reports() -> Result<()> {
        let sbom_report_service = init_sbom_report_service();

        let app = init_service(
            App::new().service(build_sbom_report_api_service(sbom_report_service)),
        )
        .await;

        let req = TestRequest::get().uri("/api/sbom-reports").to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());
        
        Ok(())
    }

    #[actix_web::test]
    async fn get_sboms_zip() -> Result<()> {
        let sbom_report_service = init_sbom_report_service();

        let app = init_service(
            App::new().service(build_sbom_report_api_service(sbom_report_service)),
        )
        .await;

        let existing_artifacts = Vec::from([
            read_test_resource(TEST_RESOURCES[0]).unwrap().report.artifact,
            read_test_resource(TEST_RESOURCES[1]).unwrap().report.artifact,
        ]);

        let req = TestRequest::post()
            .uri("/api/sbom-reports/download")
            .set_json(existing_artifacts)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        Ok(())
    }

    #[actix_web::test]
    async fn zip_with_unknown_artifact_should_fail() -> Result<()> {
        let sbom_report_service = init_sbom_report_service();

        let app = init_service(
            App::new().service(build_sbom_report_api_service(sbom_report_service)),
        )
        .await;

        let existing_artifacts = Vec::from([
            read_test_resource(TEST_RESOURCES[0]).unwrap().report.artifact,
            read_test_resource(TEST_RESOURCES[1]).unwrap().report.artifact,
        ]);

        let req = TestRequest::post()
            .uri("/api/sbom-reports/download")
            .set_json(existing_artifacts)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        Ok(())
    }
}
