use futures::{StreamExt, TryStreamExt, stream};
use kube::runtime::watcher::{Config, Event};

use kube::{Api, Client};
use tracing::warn;

use crate::controller::handler::{
    add_exposed_secret_report, add_sbom_report, add_vulnerability_report,
    delete_exposed_secret_report, delete_sbom_report, delete_vulnerability_report,
};
use crate::controller::internal::StreamEvent;
use crate::kube_types::exposed_secret_report::ImageExposedSecretReport;
use anyhow::Result;
use kube::runtime::watcher;

use crate::kube_types::sbom_report::ImageSbomReport;
use crate::kube_types::vulnerability_report::ImageVulnerabilityReport;
use crate::kube_types::{ExposedSecretReport, SbomReport, VulnerabilityReport};
use crate::states::ReportState;

pub async fn start_controller(
    vulnerability_report_shared_state: ReportState<ImageVulnerabilityReport>,
    sbom_report_shared_state: ReportState<ImageSbomReport>,
    exposed_secret_report_shared_state: ReportState<ImageExposedSecretReport>,
) -> Result<()> {
    let client = Client::try_default().await?;

    let vulnerability_report_api: Api<VulnerabilityReport> = Api::all(client.clone());
    let vulnerability_report_stream = watcher(vulnerability_report_api, Config::default())
        .map_ok(StreamEvent::VulnerabilityReport)
        .boxed();

    let sbom_report_api: Api<SbomReport> = Api::all(client.clone());
    let sbom_report_stream = watcher(sbom_report_api, Config::default())
        .map_ok(StreamEvent::SbomReport)
        .boxed();

    let exposed_secret_report_api: Api<ExposedSecretReport> = Api::all(client);
    let exposed_secret_report_stream = watcher(exposed_secret_report_api, Config::default())
        .map_ok(StreamEvent::ExposedSecretReport)
        .boxed();

    let mut combo_stream = stream::select_all(vec![
        vulnerability_report_stream,
        sbom_report_stream,
        exposed_secret_report_stream,
    ]);

    while let Some(stream_event) = combo_stream.next().await {
        match stream_event {
            // https://github.com/kube-rs/kube/issues/1615#issuecomment-2435877872
            Err(warn) => warn!(%warn, "Warning"),
            Ok(event) => match event {
                StreamEvent::VulnerabilityReport(vulnerability_report_event) => {
                    match vulnerability_report_event {
                        Event::Apply(vulnerability_report)
                        | Event::InitApply(vulnerability_report) => add_vulnerability_report(
                            vulnerability_report,
                            vulnerability_report_shared_state.clone(),
                        ),
                        Event::Delete(vulnerability_report) => delete_vulnerability_report(
                            vulnerability_report,
                            vulnerability_report_shared_state.clone(),
                        ),
                        _ => continue,
                    }
                }
                StreamEvent::SbomReport(sbom_report_event) => match sbom_report_event {
                    Event::Apply(sbom_report) | Event::InitApply(sbom_report) => {
                        add_sbom_report(sbom_report, sbom_report_shared_state.clone())
                    }
                    Event::Delete(sbom_report) => {
                        delete_sbom_report(sbom_report, sbom_report_shared_state.clone())
                    }
                    _ => continue,
                },
                StreamEvent::ExposedSecretReport(exposed_secret_report_event) => {
                    match exposed_secret_report_event {
                        Event::Apply(exposed_secret_report)
                        | Event::InitApply(exposed_secret_report) => add_exposed_secret_report(
                            exposed_secret_report,
                            exposed_secret_report_shared_state.clone(),
                        ),
                        Event::Delete(exposed_secret_report) => delete_exposed_secret_report(
                            exposed_secret_report,
                            exposed_secret_report_shared_state.clone(),
                        ),
                        _ => continue,
                    }
                }
            },
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use kube::Client;
    use tokio::sync::OnceCell;

    use crate::common_test_utils::{
        ETCD, EXPOSED_SECRET_REPORT_GVK, SBOM_REPORT_GVK, VULNERABILITY_REPORT_GVK,
        apply_test_resource, cleanup_test_namespace, delete_test_resource,
    };
    use crate::controller::start::start_controller;

    use crate::kube_types::exposed_secret_report::ImageExposedSecretReport;
    use crate::{
        kube_types::{
            sbom_report::ImageSbomReport, vulnerability_report::ImageVulnerabilityReport,
        },
        states::ReportState,
    };

    static INIT: OnceCell<()> = OnceCell::const_new();

    async fn start_test_controller(
        vulnerability_report_shared_state: ReportState<ImageVulnerabilityReport>,
        sbom_report_shared_state: ReportState<ImageSbomReport>,
        exposed_secret_report_shared_state: ReportState<ImageExposedSecretReport>,
    ) {
        INIT.get_or_init(|| async {
            let controller = start_controller(
                vulnerability_report_shared_state.clone(),
                sbom_report_shared_state.clone(),
                exposed_secret_report_shared_state.clone(),
            );

            tokio::spawn(controller);
        })
        .await;
    }

    #[tokio::test]
    async fn controller_consumes_vulnerability_reports() -> Result<()> {
        let client = Client::try_default().await?;
        let state = ReportState::<ImageVulnerabilityReport>::default();
        let gvk = VULNERABILITY_REPORT_GVK;

        cleanup_test_namespace(client.clone()).await?;
        start_test_controller(
            state.clone(),
            ReportState::<ImageSbomReport>::default(),
            ReportState::<ImageExposedSecretReport>::default(),
        )
        .await;

        apply_test_resource(client.clone(), gvk.clone(), ETCD).await?;

        let vulnerability_reports = state.reports.lock().unwrap();
        let vulnerability_owners = state.owners.lock().unwrap();

        assert!(vulnerability_reports.len() == 1);
        assert!(vulnerability_owners.len() == 1);

        drop(vulnerability_reports);
        drop(vulnerability_owners);

        delete_test_resource(client.clone(), gvk.clone(), ETCD).await?;

        let vulnerability_reports = state.reports.lock().unwrap();
        let vulnerability_owners = state.owners.lock().unwrap();

        assert!(vulnerability_reports.len() == 0);
        assert!(vulnerability_owners.len() == 0);

        Ok(())
    }

    #[tokio::test]
    async fn controller_consumes_sbom_reports() -> Result<()> {
        let client = Client::try_default().await?;
        let state = ReportState::<ImageSbomReport>::default();
        let gvk = SBOM_REPORT_GVK;

        cleanup_test_namespace(client.clone()).await?;
        start_test_controller(
            ReportState::<ImageVulnerabilityReport>::default(),
            state.clone(),
            ReportState::<ImageExposedSecretReport>::default(),
        )
        .await;

        apply_test_resource(client.clone(), gvk.clone(), ETCD).await?;

        let sbom_reports = state.reports.lock().unwrap();
        let sbom_owners = state.owners.lock().unwrap();

        assert!(sbom_reports.len() == 1);
        assert!(sbom_owners.len() == 1);

        drop(sbom_reports);
        drop(sbom_owners);

        delete_test_resource(client.clone(), gvk.clone(), ETCD).await?;

        let sbom_reports = state.reports.lock().unwrap();
        let sbom_owners = state.owners.lock().unwrap();

        assert!(sbom_reports.len() == 0);
        assert!(sbom_owners.len() == 0);

        Ok(())
    }

    #[tokio::test]
    async fn controller_consumes_exposed_secret_reports() -> Result<()> {
        let client = Client::try_default().await?;
        let state: ReportState<ImageExposedSecretReport> =
            ReportState::<ImageExposedSecretReport>::default();
        let gvk = EXPOSED_SECRET_REPORT_GVK;

        cleanup_test_namespace(client.clone()).await?;
        start_test_controller(
            ReportState::<ImageVulnerabilityReport>::default(),
            ReportState::<ImageSbomReport>::default(),
            state.clone(),
        )
        .await;

        apply_test_resource(client.clone(), gvk.clone(), ETCD).await?;

        let exposed_secret_reports = state.reports.lock().unwrap();
        let exposed_secret_owners = state.owners.lock().unwrap();

        assert!(exposed_secret_reports.len() == 1);
        assert!(exposed_secret_owners.len() == 1);

        drop(exposed_secret_reports);
        drop(exposed_secret_owners);

        delete_test_resource(client.clone(), gvk.clone(), ETCD).await?;

        let exposed_secret_reports = state.reports.lock().unwrap();
        let exposed_secret_owners = state.owners.lock().unwrap();

        assert!(exposed_secret_reports.len() == 0);
        assert!(exposed_secret_owners.len() == 0);

        Ok(())
    }
}
