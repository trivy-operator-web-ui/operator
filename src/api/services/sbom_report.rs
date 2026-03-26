use std::{
    collections::HashSet,
    io::{Cursor, Write},
};

use zip::{ZipWriter, write::SimpleFileOptions};

use crate::{
    api::{dto::SimpleSbomReportDTO, error::ZipSbomError},
    kube_types::{Artifact, sbom_report::ImageSbomReport},
    states::ReportState,
};

#[derive(Clone)]
pub struct SbomReportService {
    state: ReportState<ImageSbomReport>,
}

impl SbomReportService {
    pub fn new(state: ReportState<ImageSbomReport>) -> SbomReportService {
        SbomReportService { state }
    }

    pub fn get_simple_sbom_reports(&self) -> Vec<SimpleSbomReportDTO> {
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

                SimpleSbomReportDTO::new(
                    artifact.clone(),
                    owners.get(artifact).unwrap().len(),
                    report.summary.clone(),
                    namespaces,
                )
            })
            .collect()
    }

    pub fn zip_sboms_by_artifacts(
        &self,
        artifacts: Vec<Artifact>,
    ) -> Result<Vec<u8>, ZipSbomError> {
        let sbom_reports = self.state.reports.lock().unwrap().clone();

        let sbom_reports_artifacts: HashSet<Artifact> =
            HashSet::from_iter(sbom_reports.keys().cloned());
        let requested_artifacts: HashSet<Artifact> = HashSet::from_iter(artifacts.iter().cloned());

        let difference: HashSet<Artifact> = requested_artifacts
            .difference(&sbom_reports_artifacts)
            .cloned()
            .collect();

        match difference.len() {
            0 => {
                let buffer = vec![];
                let mut zip = ZipWriter::new(Cursor::new(buffer));

                let zip_options =
                    SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);

                for artifact in requested_artifacts.iter() {
                    let sbom = sbom_reports.get(artifact).unwrap();
                    let sbom_filename = format!("{}.json", artifact).replace("/", "_");

                    zip.start_file(sbom_filename, zip_options)
                        .map_err(|error| ZipSbomError::CreateZipError(error.to_string()))?;

                    let buffer = serde_json::to_vec(&sbom.components)
                        .map_err(|error| ZipSbomError::CreateZipError(error.to_string()))?;

                    zip.write_all(&buffer)
                        .map_err(|error| ZipSbomError::CreateZipError(error.to_string()))?;
                }

                let final_buffer = zip.finish().unwrap().get_ref().clone();
                Ok(final_buffer)
            }
            _ => Err(ZipSbomError::ArtifactsNotFound(difference)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, io::Cursor};

    use crate::api::services::tests_utils::init_sbom_report_service;
    use crate::{api::error::ZipSbomError, kube_types::Artifact};

    use anyhow::Result;
    use zip::ZipArchive;

    use crate::common_test_utils::{ETCD, RABBIT_ONE, read_test_sbom_report};

    #[test]
    fn get_simple_sbom_reports() -> Result<()> {
        let sbom_report_service = init_sbom_report_service();

        let simple_sbom_report = sbom_report_service.get_simple_sbom_reports();

        assert!(simple_sbom_report.len() == 2);

        Ok(())
    }

    #[test]
    fn zip_sbom_reports_with_known_artifacts() -> Result<()> {
        let sbom_report_service = init_sbom_report_service();

        let existing_artifacts = [
            read_test_sbom_report(ETCD).unwrap().report.artifact,
            read_test_sbom_report(RABBIT_ONE).unwrap().report.artifact,
        ]
        .to_vec();

        let sbom_report_zip = sbom_report_service.zip_sboms_by_artifacts(existing_artifacts);

        assert!(sbom_report_zip.is_ok());

        let zip = ZipArchive::new(Cursor::new(sbom_report_zip.unwrap())).unwrap();
        assert!(zip.len() == 2);

        Ok(())
    }

    #[test]
    fn zip_sbom_reports_with_unknown_artifacts() -> Result<()> {
        let sbom_report_service = init_sbom_report_service();

        let dummy_artifact = Artifact {
            digest: Some("dummy".to_string()),
            mime_type: Some("dummy".to_string()),
            repository: Some("dummy".to_string()),
            tag: Some("dummy".to_string()),
        };

        let unexisting_artifacts = [
            read_test_sbom_report(ETCD).unwrap().report.artifact,
            dummy_artifact.clone(),
        ]
        .to_vec();

        let sbom_report_zip = sbom_report_service.zip_sboms_by_artifacts(unexisting_artifacts);

        assert!(sbom_report_zip.is_err_and(
            |err| err == ZipSbomError::ArtifactsNotFound(HashSet::from([dummy_artifact]))
        ));

        Ok(())
    }
}
