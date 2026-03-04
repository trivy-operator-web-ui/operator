use crate::{
    api::{dto::Credentials, services::JwtService},
    states::{LoginUserState},
};
use actix_web::cookie::{Cookie, SameSite};
use actix_web::{
    HttpResponse, Responder, Scope, post,
    web::{Data, Json, scope},
};

pub fn build_login_service(login_user_state: LoginUserState) -> Scope {
    scope("/api/login")
        .app_data(Data::new(login_user_state))
        .service(login)
}

#[post("")]
pub async fn login(
    login_user_state: Data<LoginUserState>,
    jwt_service: Data<JwtService>,
    credentials: Json<Credentials>,
) -> impl Responder {
    if credentials.username == login_user_state.username
        && credentials.password == login_user_state.password
    {
        let token = jwt_service.generate();

        let cookie = Cookie::build("jwtToken", token.clone())
            .secure(true)
            .same_site(SameSite::Strict)
            .http_only(true)
            .finish();

        HttpResponse::Ok().cookie(cookie).json("Authenticated")
    } else {
        HttpResponse::Unauthorized().json("Invalid credentials")
    }
}
