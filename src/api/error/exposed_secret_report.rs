use crate::kube_types::Artifact;
use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct ExposedSecretReportNotFoundError {
    pub artifact: Artifact,
}

impl Display for ExposedSecretReportNotFoundError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        write!(
            f,
            "Couldn't find Exposed Secret Report for artifact {}",
            self.artifact
        )
    }
}

impl ExposedSecretReportNotFoundError {
    pub fn new(artifact: Artifact) -> ExposedSecretReportNotFoundError {
        ExposedSecretReportNotFoundError { artifact }
    }
}

impl ResponseError for ExposedSecretReportNotFoundError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(self)
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::NOT_FOUND
    }
}
