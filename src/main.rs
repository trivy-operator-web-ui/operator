use futures::prelude::*;
use kube::{
    api::Api,
    runtime::{watcher, WatchStreamExt},
    Client,
};

use std::result::Result::Ok;

use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};

use tokio;

mod data;
use data::{VulnerabilityReportSpec};
use tracing::info;


#[get("/vulnreports")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

async fn start_controller() -> anyhow::Result<()> {
    let client = Client::try_default().await?;

    let api: Api<VulnerabilityReportSpec> = Api::all(client);
    let wc = watcher::Config::default();

    let mut stream = watcher(api, wc).applied_objects().boxed();

    while let Some(event) = &stream.try_next().await? {
        println!(
            "Applied: {}",
            event.report.artifact.repository.clone().unwrap_or_default()
        );
    }
    Ok(())
}


#[tokio::main]
async fn main() -> anyhow::Result<()> {    
    let controller = start_controller();

    let server = HttpServer::new ( || {
    App::new()
        .service(web::scope("/api").service(hello))
    })
    .bind(("0.0.0.0", 8080))?
    .shutdown_timeout(5);

    tokio::join!(controller, server.run()).1?;

    Ok(())
}