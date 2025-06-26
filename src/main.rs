use futures::prelude::*;
use kube::{
    api::{Api, ObjectMeta},
    runtime::{watcher, WatchStreamExt},
    Client,
};

use web::{Data};

use std::{result::Result::Ok, sync::{Arc, Mutex}};

use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};

use tokio;

mod data;
use data::{VulnerabilityReportSpec};

#[derive(Clone, Default)]
struct State {
    vulnerability_reports: Arc<Mutex<Vec<VulnerabilityReportSpec>>>, // Mutex is necessary to mutate safely across threads
}

#[get("/vulnreports")]
async fn hello(data: Data<State>) -> impl Responder {
    let vulnerability_reports = data.vulnerability_reports.lock().unwrap().clone();

    HttpResponse::Ok().json(&vulnerability_reports)
}

fn simplify_metadata(metadata: &mut ObjectMeta) {
    metadata.finalizers = None;
    metadata.managed_fields = None;
    metadata.generation = None;
    metadata.creation_timestamp = None;
    metadata.annotations = None;
    metadata.owner_references = None;
    metadata.resource_version = None;
    metadata.uid = None;
    metadata.labels = None;
}

async fn start_controller(s: State) -> anyhow::Result<()> {
    let client = Client::try_default().await?;

    let api: Api<VulnerabilityReportSpec> = Api::all(client);
    let wc = watcher::Config::default();

    let mut stream = watcher(api, wc).applied_objects().boxed();

    while let Some(mut event) = stream.try_next().await? {
        simplify_metadata(&mut event.metadata);
    
        s.vulnerability_reports.lock().unwrap().push(event);
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let state = State::default();

    let controller = start_controller(state.clone());

    let server = HttpServer::new ( move || {
    App::new()
    .app_data(Data::new(state.clone()))
        .service(web::scope("/api").service(hello))
    })
    .bind(("0.0.0.0", 8080))?
    .shutdown_timeout(5);

    tokio::join!(controller, server.run()).1?;

    Ok(())
}