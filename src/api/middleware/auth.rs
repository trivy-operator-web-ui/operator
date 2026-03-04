use std::future::{Ready, ready};

use actix_web::{
    Error, HttpResponse,
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready},
    web::Data,
};
use futures_util::{FutureExt as _, TryFutureExt as _, future::LocalBoxFuture};

use crate::api::services::{CookieService, JwtService};

pub struct AuthenticationMiddlewareFactory;

impl<S, B> Transform<S, ServiceRequest> for AuthenticationMiddlewareFactory
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthenticationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticationMiddleware { service }))
    }
}

impl AuthenticationMiddlewareFactory {
    pub fn new() -> AuthenticationMiddlewareFactory {
        AuthenticationMiddlewareFactory {}
    }
}

pub struct AuthenticationMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for AuthenticationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let jwt_service = req
            .app_data::<Data<JwtService>>()
            .ok_or_else(|| actix_web::error::ErrorInternalServerError("JWT service missing"))
            .unwrap();

        let cookie_service = req
            .app_data::<Data<CookieService>>()
            .ok_or_else(|| actix_web::error::ErrorInternalServerError("Cookie service missing"))
            .unwrap();

        let cookie: Option<actix_web::cookie::Cookie<'_>> = cookie_service.extract_jwt_cookie(&req);

        if cookie.is_none() || !jwt_service.verify(cookie.unwrap().value().as_bytes()) {
            return Box::pin(async {
                Ok(req.into_response(HttpResponse::Unauthorized().finish().map_into_right_body()))
            });
        }

        self.service
            .call(req)
            .map_ok(ServiceResponse::map_into_left_body)
            .boxed_local()
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{
        App, HttpResponse,
        cookie::Cookie,
        http::StatusCode,
        test::{self, TestRequest, init_service},
        web::{self, Data},
    };

    use anyhow::Result;

    use crate::api::{
        middleware::AuthenticationMiddlewareFactory,
        services::tests_utils::{init_cookie_service, init_jwt_service},
    };

    #[actix_web::test]
    async fn with_no_cookie() -> Result<()> {
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(cookie_service.clone()))
                .app_data(Data::new(jwt_service.clone()))
                .route("/hey", web::get().to(|| HttpResponse::Ok()))
                .wrap(AuthenticationMiddlewareFactory::new()),
        )
        .await;

        let req = TestRequest::get().uri("/hey").to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status() == StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[actix_web::test]
    async fn with_invalid_cookie() -> Result<()> {
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(cookie_service.clone()))
                .app_data(Data::new(jwt_service.clone()))
                .route("/hey", web::get().to(|| HttpResponse::Ok()))
                .wrap(AuthenticationMiddlewareFactory::new()),
        )
        .await;

        let req = TestRequest::get()
            .uri("/hey")
            .cookie(Cookie::new("dummy", "dummy"))
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status() == StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[actix_web::test]
    async fn with_valid_cookie() -> Result<()> {
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(cookie_service.clone()))
                .app_data(Data::new(jwt_service.clone()))
                .route("/hey", web::get().to(|| HttpResponse::Ok()))
                .wrap(AuthenticationMiddlewareFactory::new()),
        )
        .await;

        let jwt = jwt_service.generate();
        let cookie = cookie_service.create_jwt_cookie(&jwt);

        let req = TestRequest::get().uri("/hey").cookie(cookie).to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status() == StatusCode::OK);

        Ok(())
    }
}
