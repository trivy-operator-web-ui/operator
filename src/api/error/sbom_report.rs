use std::collections::HashSet;

use crate::kube_types::Artifact;
use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter, Result};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum ZipSbomError {
    ArtifactsNotFound(HashSet<Artifact>),
    CreateZipError(String),
}

impl Display for ZipSbomError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            Self::ArtifactsNotFound(artifacts) => write!(
                f,
                "Could not find Sbom Reports for artifacts {:?}",
                artifacts
            ),
            Self::CreateZipError(error) => write!(f, "Could not create the Sboms Zip : {}", error),
        }
    }
}

impl ResponseError for ZipSbomError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(self)
    }

    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}
