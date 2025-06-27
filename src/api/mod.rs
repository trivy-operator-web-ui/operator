use crate::{dto::SimpleVulnerabilityReport, kubedata::VulnerabilityReport};
use crate::state::State;

use std::{result::Result::Ok};
use actix_web::body::BoxBody;
use actix_web::http::header::ContentType;
use actix_web::web::Data;
use actix_web::{web::{Path, scope}, get, App, HttpResponse, HttpServer, Responder, HttpRequest};

mod errors;
use errors::Errors;

// Responder
impl Responder for VulnerabilityReport {
    type Body = BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        let body = serde_json::to_string(&self).unwrap();

        // Create response and set content type
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(body)
    }
}

#[get("/vulnreports")]
async fn vulnreports(data: Data<State>) -> impl Responder {
    let vulnerability_reports = data.vulnerability_reports.lock().unwrap().clone();
    let iter: Vec<SimpleVulnerabilityReport> = vulnerability_reports.iter().map(|x| SimpleVulnerabilityReport::from(x.clone())).collect();
    HttpResponse::Ok().json(&iter)
}

#[get("/vulnreports/{id}")]
async fn vulnreport_by_id(data: Data<State>, uid: Path<String>) -> Result<VulnerabilityReport, Errors> {
    let vulnerability_reports = data.vulnerability_reports.lock().unwrap().clone();
    let uid = uid.into_inner();

    let report  = vulnerability_reports.into_iter().filter(|v| v.metadata.uid.clone().unwrap() == uid).next();
    match report {
        Some(r) => Ok(r),
        None => Err(Errors::VulnReportNotFound)
    }
}

pub async fn start_api(s: State) -> anyhow::Result<()> {
    let server = HttpServer::new ( move || {
    App::new()
    .app_data(Data::new(s.clone()))
        .service(scope("/api")
        .service(vulnreports)
        .service(vulnreport_by_id)
    )
    })
    .bind(("0.0.0.0", 8080))?
    .shutdown_timeout(5);

    let _ = server.run().await;

    Ok(())
}