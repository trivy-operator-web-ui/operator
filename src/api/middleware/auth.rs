use actix_web::{
    Error,
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    web,
};

use crate::{api::services::JwtService};

pub async fn authentication(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    let jwt_service = req
        .app_data::<web::Data<JwtService>>()
        .ok_or_else(|| actix_web::error::ErrorInternalServerError("JWT config missing"))?;

    let jwt = req
        .cookies()
        .unwrap()
        .iter()
        .find(|cookie| cookie.name() == "jwtToken")
        .cloned()
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Missing auth cookie"))?;

    let jwt = jwt.value().as_bytes();

    if jwt_service.verify(jwt) {
        next.call(req).await
    } else {
        Err(actix_web::error::ErrorUnauthorized(
            "Invalid token signature",
        ))
    }
}
