use actix_web::{http::{header::ContentType, StatusCode}, HttpResponse, ResponseError};
use derive_more::derive::{Display, Error};

#[derive(Debug, Display, Error)]
pub enum Errors {
    #[display("Vulnerability Report not found")]
    VulnReportNotFound
}

impl ResponseError for Errors {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::json())
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            Errors::VulnReportNotFound => StatusCode::NOT_FOUND,
        }
    }
}
