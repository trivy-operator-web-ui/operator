use std::collections::HashSet;

use crate::dto::Workload;
use crate::kube_state::SharedState;
use crate::kube_types::{SbomReport, sbom_report::ImageSbomReport};
use tracing::debug;

pub fn add_sbom_report(sbom_report: SbomReport, shared_state: SharedState<ImageSbomReport>) {
    let artifact = sbom_report.report.artifact.clone();

    let labels = sbom_report.metadata.labels.unwrap();

    let workload = Workload::new(labels);

    debug!("Event::Apply|InitApply for SBOM Report {}/{}", &workload.namespace, &workload.name);

    let mut owners = shared_state.owners.lock().unwrap();

    if let Some(x) = owners.get_mut(&artifact) {
        x.insert(workload);
    } else {
        let mut sbom_reports = shared_state.reports.lock().unwrap();
        sbom_reports.insert(artifact.clone(), sbom_report.report);
        owners.insert(artifact, HashSet::from([workload]));
    }
}

pub fn delete_sbom_report(sbom_report: SbomReport, shared_state: SharedState<ImageSbomReport>) {
    let artifact = sbom_report.report.artifact.clone();

    let labels = sbom_report.metadata.labels.unwrap();

    let workload = Workload::new(labels);

    debug!("Event::Delete for SBOM Report {}/{}", &workload.namespace, &workload.name);

    let mut owners = shared_state.owners.lock().unwrap();

    let sbom_report_owners = owners.get_mut(&artifact).unwrap();

    sbom_report_owners.remove(&workload);

    if sbom_report_owners.is_empty() {
        let mut sbom_reports = shared_state.reports.lock().unwrap();
        sbom_reports.remove(&artifact);
        owners.remove(&artifact);
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, fs};

    use anyhow::{Ok, Result};

    use crate::{
        controller::{add_sbom_report, delete_sbom_report},
        dto::Workload,
        kube_state::SharedState,
        kube_types::{SbomReport, sbom_report::ImageSbomReport},
    };

    // *************
    // ** HELPERS **
    // *************

    fn read_test_vulnerability_report(name: &str) -> Result<SbomReport> {
        let report: SbomReport = serde_yaml::from_str(&fs::read_to_string(format!(
            "test_assets/sbom_reports/{}.yaml",
            name
        ))?)?;

        Ok(report)
    }

    // ***********
    // ** TESTS **
    // ***********

    #[test]
    fn new_reports_are_added() -> Result<()> {
        let state = SharedState::<ImageSbomReport>::default();

        let rabbit = read_test_vulnerability_report("rabbit-one").unwrap();
        let etcd = read_test_vulnerability_report("etcd").unwrap();

        let rabbit_artifact = rabbit.report.artifact.clone();
        let etcd_artifact = etcd.report.artifact.clone();

        add_sbom_report(rabbit.clone(), state.clone());
        add_sbom_report(etcd.clone(), state.clone());

        let reports = state.reports.lock().unwrap();
        let owners = state.owners.lock().unwrap();

        let rabbit_owners = owners.get(&rabbit_artifact).unwrap();
        let etcd_owners = owners.get(&etcd_artifact).unwrap();

        assert!(reports.len() == 2);

        assert!(
            rabbit_owners
                == &HashSet::from([Workload {
                    kind: "Pod".to_string(),
                    name: "rabbit-one".to_string(),
                    namespace: "rabbit-one".to_string(),
                }])
        );
        assert!(
            etcd_owners
                == &HashSet::from([Workload {
                    kind: "Pod".to_string(),
                    name: "etcd-docker-desktop".to_string(),
                    namespace: "etcd".to_string(),
                }])
        );

        Ok(())
    }

    #[test]
    fn reports_with_same_artifacts_are_handled() -> Result<()> {
        let state = SharedState::<ImageSbomReport>::default();

        let rabbit_one = read_test_vulnerability_report("rabbit-one").unwrap();
        let rabbit_two = read_test_vulnerability_report("rabbit-two").unwrap();

        let artifact = rabbit_one.report.artifact.clone();

        add_sbom_report(rabbit_one.clone(), state.clone());
        add_sbom_report(rabbit_two.clone(), state.clone());

        let reports = state.reports.lock().unwrap();
        let owners = state.owners.lock().unwrap();

        let rabbit_owners = owners.get(&artifact).unwrap();

        assert!(reports.len() == 1);
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

        Ok(())
    }

    #[test]
    fn report_is_fully_deleted_when_there_are_no_more_owners() -> Result<()> {
        let state = SharedState::<ImageSbomReport>::default();

        let rabbit = read_test_vulnerability_report("rabbit-one").unwrap();
        let rabbit_artifact = rabbit.report.artifact.clone();

        add_sbom_report(rabbit.clone(), state.clone());
        delete_sbom_report(rabbit.clone(), state.clone());

        let reports = state.reports.lock().unwrap();
        let owners = state.owners.lock().unwrap();

        let rabbit_owners = owners.get(&rabbit_artifact);

        assert!(reports.len() == 0);
        assert!(rabbit_owners == None);

        Ok(())
    }

    #[test]
    fn report_is_not_deleted_if_one_or_more_owners_remain() -> Result<()> {
        let state = SharedState::<ImageSbomReport>::default();

        let rabbit_one = read_test_vulnerability_report("rabbit-one").unwrap();
        let rabbit_two = read_test_vulnerability_report("rabbit-two").unwrap();

        let artifact = rabbit_one.report.artifact.clone();

        add_sbom_report(rabbit_one.clone(), state.clone());
        add_sbom_report(rabbit_two.clone(), state.clone());
        delete_sbom_report(rabbit_one.clone(), state.clone());

        let reports = state.reports.lock().unwrap();
        let owners = state.owners.lock().unwrap();

        let rabbit_owners = owners.get(&artifact).unwrap();

        assert!(reports.len() == 1);
        assert!(
            rabbit_owners
                == &HashSet::from([Workload {
                    kind: "Pod".to_string(),
                    name: "rabbit-two".to_string(),
                    namespace: "rabbit-two".to_string(),
                }])
        );

        Ok(())
    }
}
