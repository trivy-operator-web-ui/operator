use crate::api::{
    dto::Credentials,
    services::{CookieService, JwtService, UserService},
};

use actix_web::{
    HttpResponse, Responder, Scope, post,
    web::{Data, Json, scope},
};

pub fn build_login_service(user_service: UserService) -> Scope {
    scope("/api/login")
        .app_data(Data::new(user_service))
        .service(login)
}

#[post("")]
pub async fn login(
    jwt_service: Data<JwtService>,
    cookie_service: Data<CookieService>,
    user_service: Data<UserService>,
    credentials: Json<Credentials>,
) -> impl Responder {
    if user_service.check_credentials(&credentials) {
        let token = jwt_service.generate();

        let cookie = cookie_service.create_jwt_cookie(&token);

        HttpResponse::Ok().cookie(cookie).json("Authenticated")
    } else {
        HttpResponse::Unauthorized().json("Invalid credentials")
    }
}

#[cfg(test)]
mod tests {
    use actix_web::{
        App,
        http::StatusCode,
        test::{self, TestRequest, init_service},
        web::Data,
    };
    use anyhow::Result;

    use crate::{
        api::{
            dto::Credentials,
            routes::build_login_service,
            services::{
                CookieService,
                tests_utils::{init_cookie_service, init_jwt_service, init_user_service},
            },
        },
        common_test_utils::{TEST_PASSWORD, TEST_USERNAME},
    };

    impl Credentials {
        pub fn new(username: String, password: String) -> Credentials {
            Credentials { username, password }
        }
    }

    #[actix_web::test]
    async fn login_with_invalid_credentials() -> Result<()> {
        let login_service = init_user_service();
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(jwt_service.clone()))
                .app_data(Data::new(cookie_service.clone()))
                .service(build_login_service(login_service)),
        )
        .await;

        let credentials = Credentials::new("dummy".to_string(), "dummy".to_string());

        let req = TestRequest::post()
            .uri("/api/login")
            .set_json(credentials)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status() == StatusCode::UNAUTHORIZED);

        Ok(())
    }

    #[actix_web::test]
    async fn login_with_valid_credentials() -> Result<()> {
        let login_service = init_user_service();
        let jwt_service = init_jwt_service();
        let cookie_service = init_cookie_service();

        let app = init_service(
            App::new()
                .app_data(Data::new(jwt_service.clone()))
                .app_data(Data::new(cookie_service.clone()))
                .service(build_login_service(login_service)),
        )
        .await;

        let credentials = Credentials::new(TEST_USERNAME.to_string(), TEST_PASSWORD.to_string());

        let req = TestRequest::post()
            .uri("/api/login")
            .set_json(credentials)
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status() == StatusCode::OK);
        assert!(
            resp.response()
                .cookies()
                .into_iter()
                .find(|cookie| cookie.name() == CookieService::JWT_COOKIE_NAME)
                .is_some()
        );

        Ok(())
    }
}
