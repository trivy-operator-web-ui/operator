use std::collections::HashSet;

use crate::{
    api::services::{
        CookieService, JwtService, SbomReportService, UserService, VulnerabilityReportService,
    },
    common_test_utils::{
        RESOURCES, TEST_PASSWORD, TEST_USERNAME, read_test_sbom_report,
        read_test_vulnerability_report,
    },
    kube_types::{
        Workload, sbom_report::ImageSbomReport, vulnerability_report::ImageVulnerabilityReport,
    },
    states::ReportState,
};

pub fn init_sbom_report_service() -> SbomReportService {
    let state = ReportState::<ImageSbomReport>::default();

    let mut reports = state.reports.lock().unwrap();
    let mut owners = state.owners.lock().unwrap();

    for rsc in RESOURCES {
        let vulnerability_report = read_test_sbom_report(rsc).unwrap();

        let artifact = vulnerability_report.report.artifact.clone();
        reports.insert(artifact.clone(), vulnerability_report.report);

        let labels = vulnerability_report.metadata.labels.unwrap();
        let workload = Workload::new(labels);
        owners.insert(artifact, HashSet::from([workload]));
    }

    SbomReportService::new(state.clone())
}

pub fn init_vulnerability_report_service() -> VulnerabilityReportService {
    let state = ReportState::<ImageVulnerabilityReport>::default();

    let mut reports = state.reports.lock().unwrap();
    let mut owners = state.owners.lock().unwrap();

    for rsc in RESOURCES {
        let vulnerability_report = read_test_vulnerability_report(rsc).unwrap();

        let artifact = vulnerability_report.report.artifact.clone();
        reports.insert(artifact.clone(), vulnerability_report.report);

        let labels = vulnerability_report.metadata.labels.unwrap();
        let workload = Workload::new(labels);
        owners.insert(artifact, HashSet::from([workload]));
    }

    VulnerabilityReportService::new(state.clone())
}

pub fn init_user_service() -> UserService {
    UserService::new(TEST_USERNAME.to_string(), TEST_PASSWORD.to_string())
}

pub fn init_jwt_service() -> JwtService {
    JwtService::new()
}

pub fn init_cookie_service() -> CookieService {
    CookieService::new()
}
