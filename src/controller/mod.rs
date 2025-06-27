use crate::{kubedata::VulnerabilityReport, utils::Simplify};
use crate::state::State;
use futures::{StreamExt, TryStreamExt};
use kube::{
    api::{Api},
    runtime::{watcher, WatchStreamExt},
    Client,
};

pub async fn start_controller(s: State) -> anyhow::Result<()> {
    let client = Client::try_default().await?;

    let api: Api<VulnerabilityReport> = Api::all(client);
    let wc = watcher::Config::default();

    let mut stream = watcher(api, wc).applied_objects().boxed();

    while let Some(mut event) = stream.try_next().await? {
        event.metadata.simplify();
        s.vulnerability_reports.lock().unwrap().push(event);
    }
    Ok(())
}