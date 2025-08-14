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

    watcher(api, wc)
        .applied_objects()
        .try_for_each(|mut report| {
            let reports = s.vulnerability_reports.clone();
            async move {
                report.metadata.simplify();
                reports.lock().unwrap().push(report);
                Ok(())
            }
        })
        .await?;
    Ok(())
}
