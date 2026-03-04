use futures::{StreamExt, TryStreamExt, stream};
use kube::runtime::watcher::{Config, Event};

use kube::{Api, Client};

use anyhow::Result;
use kube::runtime::watcher;

use crate::controller::{
    StreamEvent, add_sbom_report, add_vulnerability_report, delete_sbom_report,
    delete_vulnerability_report,
};
use crate::kube_types::sbom_report::ImageSbomReport;
use crate::kube_types::vulnerability_report::ImageVulnerabilityReport;
use crate::kube_types::{SbomReport, VulnerabilityReport};
use crate::states::ReportState;

pub async fn start_controller(
    vulnerability_report_shared_state: ReportState<ImageVulnerabilityReport>,
    sbom_report_shared_state: ReportState<ImageSbomReport>,
) -> Result<()> {
    let client = Client::try_default().await?;

    let vulnerability_report_api: Api<VulnerabilityReport> = Api::all(client.clone());
    let vulnerability_report_stream = watcher(vulnerability_report_api, Config::default())
        .map_ok(StreamEvent::VulnerabilityReport)
        .boxed();

    let sbom_report_api: Api<SbomReport> = Api::all(client);
    let sbom_report_stream = watcher(sbom_report_api, Config::default())
        .map_ok(StreamEvent::SbomReport)
        .boxed();

    let mut combo_stream =
        stream::select_all(vec![vulnerability_report_stream, sbom_report_stream]);

    while let Some(stream_event) = combo_stream.try_next().await? {
        match stream_event {
            StreamEvent::VulnerabilityReport(vulnerability_report_event) => {
                match vulnerability_report_event {
                    Event::Apply(vulnerability_report) | Event::InitApply(vulnerability_report) => {
                        add_vulnerability_report(
                            vulnerability_report,
                            vulnerability_report_shared_state.clone(),
                        )
                    }
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
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use anyhow::{Error, Result};
    use kube::api::{DeleteParams, DynamicObject, GroupVersionKind, ListParams, PostParams};
    use kube::{Api, Client};
    use tokio::sync::OnceCell;
    use tokio::time::sleep;

    use crate::controller::start::start_controller;
    use crate::kube_types::{SbomReport, VulnerabilityReport};
    use crate::{
        kube_types::{
            sbom_report::ImageSbomReport, vulnerability_report::ImageVulnerabilityReport,
        },
        states::ReportState,
    };

    static INIT: OnceCell<()> = OnceCell::const_new();
    static TEST_NAMESPACES: [&str; 3] = ["etcd", "rabbit-one", "rabbit-two"];

    async fn start_test_controller(
        vulnerability_report_shared_state: ReportState<ImageVulnerabilityReport>,
        sbom_report_shared_state: ReportState<ImageSbomReport>,
    ) {
        INIT.get_or_init(|| async {
            let controller = start_controller(
                vulnerability_report_shared_state.clone(),
                sbom_report_shared_state.clone(),
            );

            tokio::spawn(controller);
        })
        .await;
    }

    async fn apply_test_resource(
        client: Client,
        gvk: GroupVersionKind,
        name: &str,
    ) -> Result<DynamicObject> {
        let test_resource_folder: Result<&str> = match gvk.kind.as_str() {
            "SbomReport" => Ok("sbom_reports"),
            "VulnerabilityReport" => Ok("vulnerability_reports"),
            _ => Err(Error::msg("Unknown GVK to map to a test folder")),
        };

        let report: DynamicObject = serde_yaml::from_str(&fs::read_to_string(format!(
            "test_assets/{}/{}.yaml",
            test_resource_folder.unwrap(),
            name
        ))?)?;

        let namespace = report.metadata.clone().namespace.unwrap();

        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api = Api::<DynamicObject>::namespaced_with(client, &namespace, &ar);
        let params = PostParams::default();

        api.create(&params, &report).await?;
        sleep(Duration::from_secs(1)).await;

        Ok(report)
    }

    async fn delete_test_resource(
        client: Client,
        gvk: GroupVersionKind,
        name: &str,
    ) -> Result<DynamicObject> {
        let test_resource_folder: Result<&str> = match gvk.kind.as_str() {
            "SbomReport" => Ok("sbom_reports"),
            "VulnerabilityReport" => Ok("vulnerability_reports"),
            _ => Err(Error::msg("Unknown GVK to map to a test folder")),
        };

        let report: DynamicObject = serde_yaml::from_str(&fs::read_to_string(format!(
            "test_assets/{}/{}.yaml",
            test_resource_folder.unwrap(),
            name
        ))?)?;

        let name = report.metadata.clone().name.unwrap();
        let namespace = report.metadata.clone().namespace.unwrap();

        let (ar, _caps) = kube::discovery::pinned_kind(&client, &gvk).await?;
        let api = Api::<DynamicObject>::namespaced_with(client, &namespace, &ar);
        let params = DeleteParams::default();

        api.delete(&name, &params).await?;
        sleep(Duration::from_secs(1)).await;

        Ok(report)
    }

    async fn cleanup_test_namespace(client: Client) -> Result<()> {
        for namespace in TEST_NAMESPACES {
            let vulnerability_report_api: Api<VulnerabilityReport> =
                Api::namespaced(client.clone(), namespace);
            let sbom_report_api: Api<SbomReport> = Api::namespaced(client.clone(), namespace);

            vulnerability_report_api
                .delete_collection(&DeleteParams::default(), &ListParams::default())
                .await?;

            sbom_report_api
                .delete_collection(&DeleteParams::default(), &ListParams::default())
                .await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn controller_consumes_vulnerability_reports() -> Result<()> {
        let client = Client::try_default().await?;
        let state = ReportState::<ImageVulnerabilityReport>::default();
        let gvk =
            GroupVersionKind::gvk("aquasecurity.github.io", "v1alpha1", "VulnerabilityReport");

        cleanup_test_namespace(client.clone()).await?;
        start_test_controller(state.clone(), ReportState::<ImageSbomReport>::default()).await;

        apply_test_resource(client.clone(), gvk.clone(), "rabbit-one").await?;

        let vulnerability_reports = state.reports.lock().unwrap();
        let vulnerability_owners = state.owners.lock().unwrap();

        assert!(vulnerability_reports.len() == 1);
        assert!(vulnerability_owners.len() == 1);

        drop(vulnerability_reports);
        drop(vulnerability_owners);

        delete_test_resource(client.clone(), gvk, "rabbit-one").await?;

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
        let gvk: GroupVersionKind =
            GroupVersionKind::gvk("aquasecurity.github.io", "v1alpha1", "SbomReport");

        cleanup_test_namespace(client.clone()).await?;
        start_test_controller(
            ReportState::<ImageVulnerabilityReport>::default(),
            state.clone(),
        )
        .await;

        apply_test_resource(client.clone(), gvk.clone(), "rabbit-one").await?;

        let sbom_reports = state.reports.lock().unwrap();
        let sbom_owners = state.owners.lock().unwrap();

        assert!(sbom_reports.len() == 1);
        assert!(sbom_owners.len() == 1);

        drop(sbom_reports);
        drop(sbom_owners);

        delete_test_resource(client.clone(), gvk, "rabbit-one").await?;

        let sbom_reports = state.reports.lock().unwrap();
        let sbom_owners = state.owners.lock().unwrap();

        assert!(sbom_reports.len() == 0);
        assert!(sbom_owners.len() == 0);

        Ok(())
    }
}
