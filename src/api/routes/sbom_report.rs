use crate::{
    api::{
        error::ZipSbomError, middleware::AuthenticationMiddlewareFactory,
        services::SbomReportService,
    },
    kube_types::Artifact,
};

use actix_web::{
    HttpResponse, Responder,
    dev::HttpServiceFactory,
    get,
    http::header::{DispositionParam, DispositionType},
    post,
    web::{Data, Json, scope},
};

use chrono::Local;

use actix_web::http::header::ContentDisposition;

const SCOPE: &str = "/api/sbom-reports";

pub fn build_sbom_report_api_service(
    sbom_report_service: SbomReportService,
) -> impl HttpServiceFactory {
    scope(SCOPE)
        .app_data(Data::new(sbom_report_service))
        .service(simple_sbom_reports)
        .service(download_sbom_archive)
        .wrap(AuthenticationMiddlewareFactory::new())
}

#[get("/simple")]
async fn simple_sbom_reports(sbom_report_service: Data<SbomReportService>) -> impl Responder {
    let simple_sbom_reports = sbom_report_service.get_simple_sbom_reports();
    HttpResponse::Ok().json(&simple_sbom_reports)
}

#[post("/download")]
async fn download_sbom_archive(
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
        }
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, io::Cursor};

    use actix_web::{
        App,
        http::StatusCode,
        test::{self},
        web::Data,
    };
    use anyhow::Result;
    use test::{TestRequest, init_service};
    use zip::ZipArchive;

    use crate::{
        api::{
            dto::SimpleSbomReportDTO,
            error::ZipSbomError,
            routes::{build_sbom_report_api_service, sbom_report::SCOPE},
            services::tests_utils::{
                init_cookie_service, init_jwt_service, init_sbom_report_service,
            },
        },
        common_test_utils::{ETCD, RABBIT_ONE, read_test_sbom_report},
        kube_types::Artifact,
    };

    const SIMPLE_PATH: &str = "simple";
    const DOWNLOAD_PATH: &str = "download";

    #[actix_web::test]
    async fn service_is_authentication_protected() -> Result<()> {
        let sbom_report_service = init_sbom_report_service();
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(jwt_service.clone()))
                .app_data(Data::new(cookie_service.clone()))
                .service(build_sbom_report_api_service(sbom_report_service)),
        )
        .await;

        let path = format!("{}/{}", SCOPE, SIMPLE_PATH);
        let req = TestRequest::get().uri(&path).to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status() == StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[actix_web::test]
    async fn get_simple_reports() -> Result<()> {
        let sbom_report_service = init_sbom_report_service();
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(jwt_service.clone()))
                .app_data(Data::new(cookie_service.clone()))
                .service(build_sbom_report_api_service(sbom_report_service)),
        )
        .await;

        let token = jwt_service.generate();
        let cookie = cookie_service.create_jwt_cookie(&token);

        let path = format!("{}/{}", SCOPE, SIMPLE_PATH);
        let req = TestRequest::get().cookie(cookie).uri(&path).to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status() == StatusCode::OK);

        let resp: Vec<SimpleSbomReportDTO> = test::read_body_json(resp).await;
        assert!(resp.len() == 2);

        Ok(())
    }

    #[actix_web::test]
    async fn get_sboms_zip() -> Result<()> {
        let sbom_report_service = init_sbom_report_service();
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(jwt_service.clone()))
                .app_data(Data::new(cookie_service.clone()))
                .service(build_sbom_report_api_service(sbom_report_service)),
        )
        .await;

        let token = jwt_service.generate();
        let cookie = cookie_service.create_jwt_cookie(&token);

        let existing_artifacts = Vec::from([
            read_test_sbom_report(ETCD).unwrap().report.artifact,
            read_test_sbom_report(RABBIT_ONE).unwrap().report.artifact,
        ]);

        let path = format!("{}/{}", SCOPE, DOWNLOAD_PATH);
        let req = TestRequest::post()
            .uri(&path)
            .cookie(cookie)
            .set_json(existing_artifacts)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status() == StatusCode::OK);

        let bytes = test::read_body(resp).await;
        let zip = ZipArchive::new(Cursor::new(bytes)).unwrap();
        assert!(zip.len() == 2);

        Ok(())
    }

    #[actix_web::test]
    async fn zip_with_unknown_artifact_should_fail() -> Result<()> {
        let sbom_report_service = init_sbom_report_service();
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(jwt_service.clone()))
                .app_data(Data::new(cookie_service.clone()))
                .service(build_sbom_report_api_service(sbom_report_service)),
        )
        .await;

        let token = jwt_service.generate();
        let cookie = cookie_service.create_jwt_cookie(&token);

        let dummy_artifact = Artifact {
            digest: Some("dummy".to_string()),
            mime_type: Some("dummy".to_string()),
            repository: Some("dummy".to_string()),
            tag: Some("dummy".to_string()),
        };

        let body = Vec::from([
            read_test_sbom_report(ETCD).unwrap().report.artifact,
            dummy_artifact.clone(),
        ]);

        let path = format!("{}/{}", SCOPE, DOWNLOAD_PATH);
        let req = TestRequest::post()
            .uri(&path)
            .cookie(cookie)
            .set_json(body)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status() == StatusCode::NOT_FOUND);

        let resp: ZipSbomError = test::read_body_json(resp).await;
        assert!(resp == ZipSbomError::ArtifactsNotFound(HashSet::from([dummy_artifact])));

        Ok(())
    }
}
