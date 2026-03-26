use crate::{
    api::{
        dto::ImageExposedSecretReportDTO, error::ExposedSecretReportNotFoundError,
        middleware::AuthenticationMiddlewareFactory, services::ExposedSecretReportService,
    },
    kube_types::Artifact,
};
use actix_web::{
    HttpResponse, Responder,
    dev::HttpServiceFactory,
    get, post,
    web::{Data, Json, scope},
};

const SCOPE: &str = "/api/exposed-secret-reports";

pub fn build_exposed_secret_report_api_service(
    exposed_secret_report_service: ExposedSecretReportService,
) -> impl HttpServiceFactory {
    scope(SCOPE)
        .app_data(Data::new(exposed_secret_report_service))
        .service(simple_exposed_secret_reports)
        .service(image_exposed_secret_report)
        .wrap(AuthenticationMiddlewareFactory::new())
}

#[get("/simple")]
async fn simple_exposed_secret_reports(
    exposed_secret_report_service: Data<ExposedSecretReportService>,
) -> impl Responder {
    let simple_image_exposed_secret_reports =
        exposed_secret_report_service.get_simple_exposed_secret_report();

    HttpResponse::Ok().json(&simple_image_exposed_secret_reports)
}

#[post("/detailed")]
async fn image_exposed_secret_report(
    exposed_secret_report_service: Data<ExposedSecretReportService>,
    artifact: Json<Artifact>,
) -> Result<ImageExposedSecretReportDTO, ExposedSecretReportNotFoundError> {
    let exposed_secret_report =
        exposed_secret_report_service.get_exposed_secret_report_by_artifact(&artifact);

    match exposed_secret_report {
        Some(r) => Ok(r),
        None => Err(ExposedSecretReportNotFoundError::new(artifact.clone())),
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{
        App,
        http::StatusCode,
        test::{self},
        web::Data,
    };
    use anyhow::Result;
    use test::{TestRequest, init_service};

    use crate::{
        api::{
            dto::{ImageExposedSecretReportDTO, SimpleExposedSecretReportDTO},
            error::ExposedSecretReportNotFoundError,
            routes::{build_exposed_secret_report_api_service, exposed_secret_report::SCOPE},
            services::tests_utils::{
                init_cookie_service, init_exposed_secret_report_service, init_jwt_service,
            },
        },
        common_test_utils::{ETCD, read_test_exposed_secret_report},
        kube_types::Artifact,
    };

    const SIMPLE_PATH: &str = "simple";
    const DETAILED_PATH: &str = "detailed";

    #[actix_web::test]
    async fn service_is_authentication_protected() -> Result<()> {
        let exposed_secret_report_service = init_exposed_secret_report_service();
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(jwt_service.clone()))
                .app_data(Data::new(cookie_service.clone()))
                .service(build_exposed_secret_report_api_service(
                    exposed_secret_report_service,
                )),
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
        let exposed_secret_report_service = init_exposed_secret_report_service();
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(jwt_service.clone()))
                .app_data(Data::new(cookie_service.clone()))
                .service(build_exposed_secret_report_api_service(
                    exposed_secret_report_service,
                )),
        )
        .await;

        let token = jwt_service.generate();
        let cookie = cookie_service.create_jwt_cookie(&token);

        let path = format!("{}/{}", SCOPE, SIMPLE_PATH);
        let req = TestRequest::get().cookie(cookie).uri(&path).to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status() == StatusCode::OK);

        let resp: Vec<SimpleExposedSecretReportDTO> = test::read_body_json(resp).await;
        assert!(resp.len() == 2);

        Ok(())
    }

    #[actix_web::test]
    async fn get_existing_report() -> Result<()> {
        let exposed_secret_report_service = init_exposed_secret_report_service();
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(jwt_service.clone()))
                .app_data(Data::new(cookie_service.clone()))
                .service(build_exposed_secret_report_api_service(
                    exposed_secret_report_service,
                )),
        )
        .await;

        let token = jwt_service.generate();
        let cookie = cookie_service.create_jwt_cookie(&token);

        let artifact = read_test_exposed_secret_report(ETCD)
            .unwrap()
            .report
            .artifact;

        let path = format!("{}/{}", SCOPE, DETAILED_PATH);
        let req = test::TestRequest::post()
            .cookie(cookie)
            .uri(&path)
            .set_json(artifact.clone())
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status() == StatusCode::OK);

        let resp: ImageExposedSecretReportDTO = test::read_body_json(resp).await;
        assert!(resp.report.artifact == artifact);

        Ok(())
    }

    #[actix_web::test]
    async fn get_unexisting_report() -> Result<()> {
        let exposed_secret_report_service = init_exposed_secret_report_service();
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(jwt_service.clone()))
                .app_data(Data::new(cookie_service.clone()))
                .service(build_exposed_secret_report_api_service(
                    exposed_secret_report_service,
                )),
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

        let path = format!("{}/{}", SCOPE, DETAILED_PATH);
        let req = test::TestRequest::post()
            .uri(&path)
            .cookie(cookie)
            .set_json(dummy_artifact.clone())
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status() == StatusCode::NOT_FOUND);

        let resp: ExposedSecretReportNotFoundError = test::read_body_json(resp).await;
        assert!(resp == ExposedSecretReportNotFoundError::new(dummy_artifact));

        Ok(())
    }
}
