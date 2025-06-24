use anyhow::Ok;
use futures::prelude::*;
use kube::{
    api::{Api},
    runtime::{watcher, WatchStreamExt},
    Client,
};
mod vulnerabilityreport;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let client = Client::try_default().await?;

    let api: Api<vulnerabilityreport::VulnerabilityReportSpec> = Api::all(client);
    let wc = watcher::Config::default();

    let mut stream = watcher(api, wc).applied_objects().boxed();

    while let Some(event) = &stream.try_next().await? {
        println!("Applied: {}", event.report.artifact.repository.clone().unwrap_or_default());
    }

    Ok(())
}