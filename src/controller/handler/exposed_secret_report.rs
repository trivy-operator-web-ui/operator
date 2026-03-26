use std::collections::HashSet;

use tracing::debug;

use crate::kube_types::exposed_secret_report::ImageExposedSecretReport;
use crate::kube_types::{ExposedSecretReport, Workload};
use crate::states::ReportState;

pub fn add_exposed_secret_report(
    exposed_secret_report: ExposedSecretReport,
    shared_state: ReportState<ImageExposedSecretReport>,
) {
    let artifact = exposed_secret_report.report.artifact.clone();

    let labels = exposed_secret_report.metadata.labels.unwrap();

    let workload = Workload::new(labels);

    debug!(
        "Event::Apply|InitApply for Exposed Secret Report {}/{}",
        &workload.namespace, &workload.name
    );

    let mut owners = shared_state.owners.lock().unwrap();

    if let Some(x) = owners.get_mut(&artifact) {
        x.insert(workload);
    } else {
        let mut exposed_secret_reports = shared_state.reports.lock().unwrap();
        exposed_secret_reports.insert(artifact.clone(), exposed_secret_report.report);
        owners.insert(artifact, HashSet::from([workload]));
    }
}

pub fn delete_exposed_secret_report(
    exposed_secret_report: ExposedSecretReport,
    shared_state: ReportState<ImageExposedSecretReport>,
) {
    let artifact = exposed_secret_report.report.artifact.clone();

    let labels = exposed_secret_report.metadata.labels.unwrap();

    let workload = Workload::new(labels);

    debug!(
        "Event::Delete for Exposed Secret Report {}/{}",
        &workload.namespace, &workload.name
    );

    let mut owners = shared_state.owners.lock().unwrap();
    let exposed_secret_report_owners = owners.get_mut(&artifact).unwrap();

    exposed_secret_report_owners.remove(&workload);

    if exposed_secret_report_owners.is_empty() {
        let mut exposed_secret_reports = shared_state.reports.lock().unwrap();
        exposed_secret_reports.remove(&artifact);
        owners.remove(&artifact);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use anyhow::{Ok, Result};

    use crate::{
        common_test_utils::{ETCD, RABBIT_ONE, RABBIT_TWO, read_test_exposed_secret_report},
        controller::handler::exposed_secret_report::{
            add_exposed_secret_report, delete_exposed_secret_report,
        },
        kube_types::{Workload, exposed_secret_report::ImageExposedSecretReport},
        states::ReportState,
    };

    #[test]
    fn new_reports_are_added() -> Result<()> {
        let state = ReportState::<ImageExposedSecretReport>::default();

        let rabbit = read_test_exposed_secret_report(RABBIT_ONE).unwrap();
        let etcd = read_test_exposed_secret_report(ETCD).unwrap();

        let rabbit_artifact = rabbit.report.artifact.clone();
        let etcd_artifact = etcd.report.artifact.clone();

        add_exposed_secret_report(rabbit.clone(), state.clone());
        add_exposed_secret_report(etcd.clone(), state.clone());

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
        let state = ReportState::<ImageExposedSecretReport>::default();

        let rabbit_one = read_test_exposed_secret_report(RABBIT_ONE).unwrap();
        let rabbit_two = read_test_exposed_secret_report(RABBIT_TWO).unwrap();

        let artifact = rabbit_one.report.artifact.clone();

        add_exposed_secret_report(rabbit_one.clone(), state.clone());
        add_exposed_secret_report(rabbit_two.clone(), state.clone());

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
        let state = ReportState::<ImageExposedSecretReport>::default();

        let rabbit = read_test_exposed_secret_report(RABBIT_ONE).unwrap();
        let rabbit_artifact = rabbit.report.artifact.clone();

        add_exposed_secret_report(rabbit.clone(), state.clone());
        delete_exposed_secret_report(rabbit.clone(), state.clone());

        let reports = state.reports.lock().unwrap();
        let owners = state.owners.lock().unwrap();

        let rabbit_owners = owners.get(&rabbit_artifact);

        assert!(reports.len() == 0);
        assert!(rabbit_owners == None);

        Ok(())
    }

    #[test]
    fn report_is_not_deleted_if_one_or_more_owners_remain() -> Result<()> {
        let state = ReportState::<ImageExposedSecretReport>::default();

        let rabbit_one = read_test_exposed_secret_report(RABBIT_ONE).unwrap();
        let rabbit_two = read_test_exposed_secret_report(RABBIT_TWO).unwrap();

        let artifact = rabbit_one.report.artifact.clone();

        add_exposed_secret_report(rabbit_one.clone(), state.clone());
        add_exposed_secret_report(rabbit_two.clone(), state.clone());
        delete_exposed_secret_report(rabbit_one.clone(), state.clone());

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
