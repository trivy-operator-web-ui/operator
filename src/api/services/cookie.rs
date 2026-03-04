use actix_web::{
    cookie::{Cookie, SameSite},
    dev::ServiceRequest,
};

#[derive(Clone)]
pub struct CookieService;

impl CookieService {
    pub const JWT_COOKIE_NAME: &'static str = "jwtToken";

    pub fn new() -> CookieService {
        CookieService {}
    }

    pub fn create_jwt_cookie(&self, jwt_token: &str) -> Cookie<'static> {
        Cookie::build(Self::JWT_COOKIE_NAME, jwt_token.to_owned())
            .secure(true)
            .same_site(SameSite::Strict)
            .http_only(true)
            .finish()
    }

    pub fn extract_jwt_cookie(&self, req: &ServiceRequest) -> Option<Cookie<'static>> {
        req.cookies()
            .unwrap()
            .iter()
            .find(|cookie| cookie.name() == Self::JWT_COOKIE_NAME)
            .cloned()
    }
}
