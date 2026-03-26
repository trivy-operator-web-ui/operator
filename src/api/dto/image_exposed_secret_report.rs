use std::collections::HashSet;

use actix_web::{HttpRequest, HttpResponse, Responder, body::BoxBody};
use serde::{Deserialize, Serialize};

use crate::kube_types::{Workload, exposed_secret_report::ImageExposedSecretReport};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub struct ImageExposedSecretReportDTO {
    pub report: ImageExposedSecretReport,
    pub owners: HashSet<Workload>,
}

impl Responder for ImageExposedSecretReportDTO {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        HttpResponse::Ok().json(&self)
    }
}

impl ImageExposedSecretReportDTO {
    pub fn new(
        report: ImageExposedSecretReport,
        owners: HashSet<Workload>,
    ) -> ImageExposedSecretReportDTO {
        ImageExposedSecretReportDTO { report, owners }
    }
}
