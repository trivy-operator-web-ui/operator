use actix_web::{HttpResponse, Responder, dev::HttpServiceFactory, get, web::scope};

const SCOPE: &str = "/api/health";

pub fn build_health_api_service() -> impl HttpServiceFactory {
    scope(SCOPE).service(health)
}

#[get("")]
pub async fn health() -> impl Responder {
    HttpResponse::Ok().json("Healthy")
}

#[cfg(test)]
mod tests {
    use actix_web::{
        App,
        http::StatusCode,
        test::{self},
    };
    use anyhow::Result;
    use test::{TestRequest, init_service};

    use crate::api::routes::{build_health_api_service, health::SCOPE};

    #[actix_web::test]
    async fn service_is_authentication_protected() -> Result<()> {
        let app = init_service(App::new().service(build_health_api_service())).await;

        let req = TestRequest::get().uri(SCOPE).to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status() == StatusCode::OK);

        Ok(())
    }
}
