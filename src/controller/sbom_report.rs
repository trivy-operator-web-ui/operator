use std::collections::HashSet;

use crate::dto::Workload;
use crate::kube_types::{SbomReport, sbom_report::ImageSbomReport};
use crate::kube_state::SharedState;

use kube::runtime::watcher;
use kube::runtime::watcher::{Config, Event};

use futures::{StreamExt, TryStreamExt};
use kube::{Client, api::Api};

pub async fn start_sbom_report_controller(
    shared_state: SharedState<ImageSbomReport>,
    client: Client,
) -> anyhow::Result<()> {
    let api: Api<SbomReport> = Api::all(client);

    let mut stream = watcher(api, Config::default()).boxed();

    while let Some(status) = stream.try_next().await? {
        match status {
            Event::Apply(sbom_report) | Event::InitApply(sbom_report) => {
                let artifact = sbom_report.report.artifact.clone();

                let labels = sbom_report.metadata.labels.unwrap();

                let workload = Workload::new(labels);

                let mut owners = shared_state.owners.lock().unwrap();

                if let Some(x) = owners.get_mut(&artifact) {
                    x.insert(workload);
                } else {
                    let mut sbom_reports = shared_state.reports.lock().unwrap();
                    sbom_reports.insert(artifact.clone(), sbom_report.report);
                    owners.insert(artifact, HashSet::from([workload]));
                }
            }
            Event::Delete(sbom_report) => {
                let artifact = sbom_report.report.artifact.clone();

                let labels = sbom_report.metadata.labels.unwrap();

                let workload = Workload::new(labels);

                let mut owners = shared_state.owners.lock().unwrap();

                let sbom_report_owners = owners.get_mut(&artifact).unwrap();

                sbom_report_owners.remove(&workload);

                if sbom_report_owners.is_empty() {
                    let mut sbom_reports = shared_state.reports.lock().unwrap();
                    sbom_reports.remove(&artifact);
                    owners.remove(&artifact);
                }
            }
            _ => {
                continue;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // *************
    // ** HELPERS **
    // *************

    use anyhow::Result;
    use kube::{
        Api, Client,
        api::{DeleteParams, ListParams, PostParams},
    };
    use std::{collections::HashSet, fs, time::Duration};
    use tokio::{sync::OnceCell, time::sleep};

    use crate::{
        controller::start_sbom_report_controller,
        dto::Workload,
        kube_types::{SbomReport, sbom_report::ImageSbomReport},
        kube_state::SharedState,
    };

    static INIT: OnceCell<()> = OnceCell::const_new();
    static TEST_NAMESPACES: [&str; 3] = ["kube-system", "rabbit-one", "rabbit-two"];

    async fn cleanup_test_namespace(client: Client) -> Result<()> {
        for namespace in TEST_NAMESPACES {
            let api: Api<SbomReport> = Api::namespaced(client.clone(), namespace);
            api.delete_collection(&DeleteParams::default(), &ListParams::default())
                .await?;
        }
        Ok(())
    }

    async fn apply_test_resource(client: Client, name: &str) -> Result<SbomReport> {
        let report: SbomReport = serde_yaml::from_str(&fs::read_to_string(format!(
            "test_assets/sbom_reports/{}.yaml",
            name
        ))?)?;

        let namespace = report.metadata.clone().namespace.unwrap();

        let api: Api<SbomReport> = Api::namespaced(client, &namespace);
        let params = PostParams::default();
        api.create(&params, &report).await?;
        sleep(Duration::from_secs(1)).await;

        Ok(report)
    }

    async fn delete_test_resource(client: Client, name: &str) -> Result<SbomReport> {
        let report: SbomReport = serde_yaml::from_str(&fs::read_to_string(format!(
            "test_assets/sbom_reports/{}.yaml",
            name
        ))?)?;

        let name = report.metadata.clone().name.unwrap();
        let namespace = report.metadata.clone().namespace.unwrap();

        let api: Api<SbomReport> = Api::namespaced(client, &namespace);
        let params = DeleteParams::default();
        api.delete(&name, &params).await?;
        sleep(Duration::from_secs(1)).await;

        Ok(report)
    }

    async fn start_controller(state: SharedState<ImageSbomReport>) {
        INIT.get_or_init(|| async {
            let sbom_report_controller_client = Client::try_default()
                .await
                .expect("Coudln't create test controller client");
            let sbom_report_controller =
                start_sbom_report_controller(state.clone(), sbom_report_controller_client);
            tokio::spawn(sbom_report_controller);
        })
        .await;
    }

    // ***********
    // ** TESTS **
    // ***********

    #[tokio::test]
    async fn controller_consumes() -> Result<()> {
        let client = Client::try_default().await?;
        cleanup_test_namespace(client.clone()).await?;

        let state = SharedState::<ImageSbomReport>::default();
        start_controller(state.clone()).await;

        apply_test_resource(client.clone(), "coredns").await?;

        let reports = state.reports.lock().unwrap();

        assert!(reports.len() == 1);

        Ok(())
    }

    #[tokio::test]
    async fn controller_handles_duplicate() -> Result<()> {
        let client = Client::try_default().await?;
        cleanup_test_namespace(client.clone()).await?;

        let state = SharedState::<ImageSbomReport>::default();
        start_controller(state.clone()).await;

        let etcd = apply_test_resource(client.clone(), "etcd").await?;

        let reports = state.reports.lock().unwrap();
        let owners = state.owners.lock().unwrap();
        let etcd_owners = owners.get(&etcd.report.artifact).unwrap();

        assert!(reports.len() == 1);
        assert!(etcd_owners.len() == 1);
        assert!(
            etcd_owners
                == &HashSet::from([Workload {
                    kind: "Pod".to_string(),
                    name: "etcd-docker-desktop".to_string(),
                    namespace: "kube-system".to_string(),
                }])
        );
        drop(reports);
        drop(owners);

        let rabbit_one = apply_test_resource(client.clone(), "rabbit-one")
            .await
            .unwrap();

        let reports = state.reports.lock().unwrap();
        let owners = state.owners.lock().unwrap();
        let rabbit_owners = owners.get(&rabbit_one.report.artifact).unwrap();

        assert!(reports.len() == 2);
        assert!(rabbit_owners.len() == 1);
        drop(reports);
        drop(owners);

        apply_test_resource(client.clone(), "rabbit-two").await?;

        let reports = state.reports.lock().unwrap();
        let owners = state.owners.lock().unwrap();
        let rabbit_owners = owners.get(&rabbit_one.report.artifact).unwrap();

        assert!(reports.len() == 2);
        assert!(rabbit_owners.len() == 2);
        assert!(
            rabbit_owners
                == &HashSet::from([
                    Workload {
                        kind: "Pod".to_string(),
                        name: "rabbit-one".to_string(),
                        namespace: "rabbit-one".to_string(),
                    },
                    Workload {
                        kind: "Pod".to_string(),
                        name: "rabbit-two".to_string(),
                        namespace: "rabbit-two".to_string(),
                    }
                ])
        );

        drop(reports);
        drop(owners);

        delete_test_resource(client.clone(), "rabbit-two").await?;

        let reports = state.reports.lock().unwrap();
        let owners = state.owners.lock().unwrap();
        let rabbit_owners = owners.get(&rabbit_one.report.artifact).unwrap();

        assert!(reports.len() == 2);
        assert!(rabbit_owners.len() == 1);
        assert!(
            rabbit_owners
                == &HashSet::from([Workload {
                    kind: "Pod".to_string(),
                    name: "rabbit-one".to_string(),
                    namespace: "rabbit-one".to_string(),
                }])
        );

        drop(reports);
        drop(owners);

        delete_test_resource(client.clone(), "rabbit-one").await?;

        let reports = state.reports.lock().unwrap();
        let owners = state.owners.lock().unwrap();
        let rabbit_owners = owners.get(&rabbit_one.report.artifact);

        assert!(reports.len() == 1);
        assert!(rabbit_owners.is_none());

        Ok(())
    }
}
