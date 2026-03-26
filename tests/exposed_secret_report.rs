use anyhow::{Ok, Result};
use awc::cookie::Cookie;

use awc::http::StatusCode;
use kube::Client;

use trivy_operator_web_ui::api::dto::{ImageExposedSecretReportDTO, SimpleExposedSecretReportDTO};
use trivy_operator_web_ui::kube_types::{Artifact, ExposedSecretReport};

mod utils;
use crate::utils::{
    ETCD, EXPOSED_SECRET_REPORT_GVK, apply_test_resource, cleanup_test_namespace,
    delete_test_resource, get_jwt_from_api, get_test_endpoint,
};

#[actix_web::test]
async fn service_is_protected() -> Result<()> {
    let http_client = awc::Client::default();
    let endpoint = get_test_endpoint();

    let res = http_client
        .get(format!("{}/api/exposed-secret-reports/simple", &endpoint))
        .send()
        .await
        .unwrap();

    assert!(res.status() == StatusCode::UNAUTHORIZED);

    let dummy_artifact = Artifact {
        digest: Some("dummy".to_string()),
        mime_type: Some("dummy".to_string()),
        repository: Some("dummy".to_string()),
        tag: Some("dummy".to_string()),
    };

    let res = http_client
        .post(format!("{}/api/exposed-secret-reports/detailed", &endpoint))
        .send_json(&dummy_artifact)
        .await
        .unwrap();

    assert!(res.status() == StatusCode::UNAUTHORIZED);

    Ok(())
}

#[actix_web::test]
async fn events() -> Result<()> {
    let client: Client = Client::try_default().await?;
    let http_client = awc::Client::default();
    let gvk = EXPOSED_SECRET_REPORT_GVK;

    let endpoint = get_test_endpoint();

    cleanup_test_namespace(client.clone()).await?;

    let etcd = apply_test_resource(client.clone(), gvk.clone(), ETCD)
        .await?
        .try_parse::<ExposedSecretReport>()
        .unwrap();

    let jwt = get_jwt_from_api(http_client.clone()).await;

    let simple_reports = http_client
        .get(format!("{}/api/exposed-secret-reports/simple", &endpoint))
        .cookie(Cookie::new("jwtToken", &jwt))
        .send()
        .await
        .unwrap()
        .json::<Vec<SimpleExposedSecretReportDTO>>()
        .await?;

    assert!(simple_reports.len() == 1);

    let detailed_report = http_client
        .post(format!("{}/api/exposed-secret-reports/detailed", &endpoint))
        .cookie(Cookie::new("jwtToken", &jwt))
        .send_json(&etcd.report.artifact)
        .await
        .unwrap()
        .json::<ImageExposedSecretReportDTO>()
        .await?;

    assert!(detailed_report.report.artifact == etcd.report.artifact);

    delete_test_resource(client.clone(), gvk.clone(), ETCD).await?;

    let simple_reports = http_client
        .get(format!("{}/api/exposed-secret-reports/simple", &endpoint))
        .cookie(Cookie::new("jwtToken", &jwt))
        .send()
        .await
        .unwrap()
        .json::<Vec<SimpleExposedSecretReportDTO>>()
        .await?;

    assert!(simple_reports.is_empty());

    Ok(())
}
