use std::collections::HashSet;

use crate::api::dto::{ImageExposedSecretReportDTO, SimpleExposedSecretReportDTO};
use crate::kube_types::Artifact;
use crate::kube_types::exposed_secret_report::ImageExposedSecretReport;
use crate::states::ReportState;

#[derive(Clone)]
pub struct ExposedSecretReportService {
    state: ReportState<ImageExposedSecretReport>,
}

impl ExposedSecretReportService {
    pub fn new(state: ReportState<ImageExposedSecretReport>) -> ExposedSecretReportService {
        ExposedSecretReportService { state }
    }

    pub fn get_simple_exposed_secret_report(&self) -> Vec<SimpleExposedSecretReportDTO> {
        self.state
            .reports
            .lock()
            .unwrap()
            .iter()
            .map(|(artifact, report)| {
                let owners = self.state.owners.lock().unwrap();

                let namespaces: HashSet<String> = owners
                    .get(artifact)
                    .unwrap()
                    .iter()
                    .map(|workload| workload.namespace.clone())
                    .collect();

                SimpleExposedSecretReportDTO::new(
                    artifact.clone(),
                    owners.get(artifact).unwrap().len(),
                    report.summary.clone(),
                    namespaces,
                )
            })
            .collect()
    }

    pub fn get_exposed_secret_report_by_artifact(
        &self,
        artifact: &Artifact,
    ) -> Option<ImageExposedSecretReportDTO> {
        let exposed_secret_reports = self.state.reports.lock().unwrap();
        let report = exposed_secret_reports.get(artifact);

        report.map(|r| {
            let owners = self.state.owners.lock().unwrap();
            let exposed_secret_report_ownsers = owners.get(artifact).unwrap();
            ImageExposedSecretReportDTO::new(r.clone(), exposed_secret_report_ownsers.clone())
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        api::services::tests_utils::init_exposed_secret_report_service,
        common_test_utils::{ETCD, read_test_exposed_secret_report},
        kube_types::Artifact,
    };

    use anyhow::Result;

    #[test]
    fn get_simple_exposed_secret_report() -> Result<()> {
        let exposed_secret_report_service = init_exposed_secret_report_service();

        let simple_vulnerability_report =
            exposed_secret_report_service.get_simple_exposed_secret_report();

        assert!(simple_vulnerability_report.len() == 2);

        Ok(())
    }

    #[test]
    fn get_exposed_secret_report_by_artifact() -> Result<()> {
        let exposed_secret_report_service = init_exposed_secret_report_service();

        let existing_artifact = read_test_exposed_secret_report(ETCD)
            .unwrap()
            .report
            .artifact;

        let exposed_secret_report =
            exposed_secret_report_service.get_exposed_secret_report_by_artifact(&existing_artifact);

        assert!(exposed_secret_report.is_some());
        assert!(exposed_secret_report.unwrap().report.artifact == existing_artifact);

        Ok(())
    }

    #[test]
    fn get_exposed_secret_report_by_unknown_artifact() -> Result<()> {
        let exposed_secret_report_service = init_exposed_secret_report_service();

        let dummy_artifact = Artifact {
            digest: Some("dummy".to_string()),
            mime_type: Some("dummy".to_string()),
            repository: Some("dummy".to_string()),
            tag: Some("dummy".to_string()),
        };

        let exposed_secret_report =
            exposed_secret_report_service.get_exposed_secret_report_by_artifact(&dummy_artifact);

        assert!(exposed_secret_report.is_none());
        Ok(())
    }
}
