use crate::{
    api::error::ZipSbomError,
    dto::{SbomsToZip, SimpleSbomReportDTO},
    kube_types::{Artifact, sbom_report::ImageSbomReport},
    kube_state::SharedState,
};

use actix_web::{
    HttpResponse, Responder, Scope, get,
    http::header::{DispositionParam, DispositionType},
    post,
    web::{Data, Json, scope},
};

use chrono::Local;
use std::{
    collections::HashSet,
    io::{Cursor, Write},
};
use zip::{ZipWriter, write::SimpleFileOptions};

use actix_web::http::header::ContentDisposition;

pub fn build_sbom_report_api_scope(sbom_report_state: SharedState<ImageSbomReport>) -> Scope {
    scope("/api/sbom-reports")
        .app_data(Data::new(sbom_report_state))
        .service(simple_sbom_reports)
        .service(download_sbom_archive)
}

#[get("")]
async fn simple_sbom_reports(data: Data<SharedState<ImageSbomReport>>) -> impl Responder {
    let simple_sbom_reports: Vec<SimpleSbomReportDTO> = data
        .reports
        .lock()
        .unwrap()
        .iter()
        .map(|(artifact, report)| {
            let owners = data.owners.lock().unwrap();

            let namespaces: HashSet<String> = owners
                .get(artifact)
                .unwrap()
                .iter()
                .map(|workload| workload.namespace.clone())
                .collect();

            SimpleSbomReportDTO::new(
                artifact.clone(),
                owners.get(artifact).unwrap().len(),
                report.summary.clone(),
                namespaces,
            )
        })
        .collect();

    HttpResponse::Ok().json(&simple_sbom_reports)
}

#[post("/download")]
async fn download_sbom_archive(
    data: Data<SharedState<ImageSbomReport>>,
    info: Json<SbomsToZip>,
) -> Result<HttpResponse, ZipSbomError> {
    let sbom_reports = data.reports.lock().unwrap().clone();

    let sbom_reports_artifacts = HashSet::from_iter(sbom_reports.keys().cloned());
    let requested_artifacts = &info.artifacts;

    let difference: HashSet<Artifact> = requested_artifacts
        .difference(&sbom_reports_artifacts)
        .cloned()
        .collect();

    match difference.len() {
        0 => {
            let buffer = vec![];
            let zip_date = Local::now().format("%Y_%m_%d_%Hh%M").to_string();
            let zip_filename = format!("sbom_{zip_date}.zip");

            let mut zip = ZipWriter::new(Cursor::new(buffer));

            let zip_options =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

            for artifact in requested_artifacts.iter() {
                let sbom = sbom_reports.get(artifact).unwrap();
                let sbom_filename = format!("{}.json", artifact).replace("/", "_");

                zip.start_file(sbom_filename, zip_options)
                    .map_err(|error| ZipSbomError::CreateZipError(error.to_string()))?;

                let buffer = serde_json::to_vec(&sbom.components)
                    .map_err(|error| ZipSbomError::CreateZipError(error.to_string()))?;

                zip.write_all(&buffer)
                    .map_err(|error| ZipSbomError::CreateZipError(error.to_string()))?;
            }

            let final_buffer = zip.finish().unwrap().get_ref().clone();
            Ok(HttpResponse::Ok()
                .content_type("application/zip")
                .append_header(ContentDisposition {
                    disposition: DispositionType::Attachment,
                    parameters: vec![DispositionParam::Filename(zip_filename)],
                })
                .body(final_buffer))
        }
        _ => Err(ZipSbomError::ArtifactsNotFound(difference)),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs};

    use actix_web::{
        App,
        test::{self},
    };
    use anyhow::Result;
    use std::io::Cursor;
    use test::{TestRequest, call_and_read_body, call_and_read_body_json, init_service};
    use zip::ZipArchive;

    use crate::{
        api::{build_sbom_report_api_scope, error::ZipSbomError},
        dto::{SbomsToZip, SimpleSbomReportDTO, Workload},
        kube_types::{Artifact, SbomReport, sbom_report::ImageSbomReport},
        kube_state::SharedState,
    };

    impl SbomsToZip {
        pub fn new(artifacts: HashSet<Artifact>) -> SbomsToZip {
            SbomsToZip { artifacts }
        }
    }

    static TEST_RESOURCES: [&str; 3] = ["coredns", "etcd", "rabbit-one"];

    fn read_test_resource(name: &str) -> Result<SbomReport> {
        let report: SbomReport = serde_yaml::from_str(&fs::read_to_string(format!(
            "test_assets/sbom_reports/{}.yaml",
            name
        ))?)?;

        Ok(report)
    }

    fn init_state() -> Result<SharedState<ImageSbomReport>> {
        let state = SharedState::<ImageSbomReport>::default();

        let mut reports = state.reports.lock().unwrap();
        let mut owners = state.owners.lock().unwrap();

        for rsc in TEST_RESOURCES {
            let sbom_report = read_test_resource(rsc).unwrap();

            let artifact = sbom_report.report.artifact.clone();
            reports.insert(artifact.clone(), sbom_report.report);

            let labels = sbom_report.metadata.labels.unwrap();
            let workload = Workload::new(labels);
            owners.insert(artifact, HashSet::from([workload]));
        }

        Ok(state.clone())
    }

    fn get_api_snapshot(name: &str) -> Result<Vec<SimpleSbomReportDTO>> {
        let snapshot: Vec<SimpleSbomReportDTO> = serde_yaml::from_str(&fs::read_to_string(
            format!("test_assets/api_snapshots/sbom_reports/{}.json", name),
        )?)?;

        Ok(snapshot)
    }

    #[actix_web::test]
    async fn get_simple_reports() -> Result<()> {
        let sbom_report_state = init_state().unwrap();

        let app = init_service(
            App::new().service(build_sbom_report_api_scope(sbom_report_state.clone())),
        )
        .await;

        let req = TestRequest::get().uri("/api/sbom-reports").to_request();

        let response: Vec<SimpleSbomReportDTO> = call_and_read_body_json(&app, req).await;

        let snapshot: Vec<SimpleSbomReportDTO> = get_api_snapshot("get_simple_reports").unwrap();

        // Collect to a Vec from a HashSet randomly places element, so an assert_eq between Vecs won't work
        assert!(
            response.len() == 3
                && response.contains(&snapshot[0])
                && response.contains(&snapshot[1])
                && response.contains(&snapshot[2])
        );

        Ok(())
    }

    #[actix_web::test]
    async fn get_sboms_zip() -> Result<()> {
        let sbom_report_state = init_state().unwrap();

        let app = init_service(
            App::new().service(build_sbom_report_api_scope(sbom_report_state.clone())),
        )
        .await;

        let mut sboms_to_zip: HashSet<Artifact> = HashSet::new();
        for artifact in sbom_report_state.owners.lock().unwrap().keys().cloned() {
            sboms_to_zip.insert(artifact);
        }

        let data = SbomsToZip::new(sboms_to_zip);

        let req = TestRequest::post()
            .uri("/api/sbom-reports/download")
            .set_json(data)
            .to_request();

        let response = call_and_read_body(&app, req).await;

        let zip = ZipArchive::new(Cursor::new(response)).unwrap();
        assert!(zip.len() == 3);

        Ok(())
    }

    #[actix_web::test]
    async fn zip_with_unknown_artifact_should_fail() -> Result<()> {
        let sbom_report_state = init_state().unwrap();

        let app = init_service(
            App::new().service(build_sbom_report_api_scope(sbom_report_state.clone())),
        )
        .await;

        let mut sboms_to_zip: HashSet<Artifact> = HashSet::new();
        for artifact in sbom_report_state.owners.lock().unwrap().keys().cloned() {
            sboms_to_zip.insert(artifact);
        }

        let unknown_artifact = Artifact {
            digest: Option::Some(String::from("dummy")),
            mime_type: None,
            repository: Option::Some(String::from("dummy")),
            tag: Option::Some(String::from("dummy")),
        };

        sboms_to_zip.insert(unknown_artifact.clone());

        let data = SbomsToZip::new(sboms_to_zip);

        let req = TestRequest::post()
            .uri("/api/sbom-reports/download")
            .set_json(data)
            .to_request();

        let response: ZipSbomError = call_and_read_body_json(&app, req).await;

        assert!(response == ZipSbomError::ArtifactsNotFound(HashSet::from([unknown_artifact])));

        Ok(())
    }
}
