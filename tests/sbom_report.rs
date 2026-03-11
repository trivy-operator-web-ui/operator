use anyhow::Result;
use awc::{cookie::Cookie, http::StatusCode};
use kube::Client;
use trivy_operator_web_ui::{api::dto::SimpleSbomReportDTO, common_test_utils::{SBOM_REPORT_GVK, get_test_endpoint}, kube_types::{Artifact, SbomReport}};

#[actix_web::test]
async fn service_is_protected() -> Result<()> {
    let http_client = awc::Client::default();
    let endpoint = get_test_endpoint();

    let res = http_client
        .get(format!("{}/api/sbom-reports/simple", &endpoint))
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
        .post(format!("{}/api/sbom-reports/download", &endpoint))
        .send_json(&vec![dummy_artifact])
        .await
        .unwrap();

    assert!(res.status() == StatusCode::UNAUTHORIZED);

    Ok(())
}


#[actix_web::test]
async fn events() -> Result<()> {
    let client: Client = Client::try_default().await?;
    let http_client = awc::Client::default();
    let gvk = SBOM_REPORT_GVK;

    let endpoint = get_test_endpoint();

    cleanup_test_namespace(client.clone()).await?;

    apply_test_resource(client.clone(), gvk.clone(), ETCD).await?;

    let jwt = get_jwt_from_api(http_client.clone()).await;

    let simple_reports = http_client
        .get(format!("{}/api/sbom-reports/simple", &endpoint))
        .cookie(Cookie::new("jwtToken", &jwt))
        .send()
        .await
        .unwrap()
        .json::<Vec<SimpleSbomReportDTO>>()
        .await?;

    assert!(simple_reports.len() == 1);

    delete_test_resource(client.clone(), gvk.clone(), ETCD).await?;

    let simple_reports = http_client
        .get(format!("{}/api/sbom-reports/simple", &endpoint))
        .cookie(Cookie::new("jwtToken", &jwt))
        .send()
        .await
        .unwrap()
        .json::<Vec<SimpleSbomReportDTO>>()
        .await?;

    assert!(simple_reports.is_empty());

    Ok(())
}

#[actix_web::test]
async fn zip_sbom_reports() -> Result<()> {
let client: Client = Client::try_default().await?;
    let http_client = awc::Client::default();
    let gvk = SBOM_REPORT_GVK;

    let endpoint = get_test_endpoint();

    cleanup_test_namespace(client.clone()).await?;

    let etcd = apply_test_resource(client.clone(), gvk.clone(), ETCD)
        .await?
        .try_parse::<SbomReport>()
        .unwrap();

    let rabbit_one = apply_test_resource(client.clone(), gvk.clone(), RABBIT_ONE)
        .await?
        .try_parse::<SbomReport>()
        .unwrap();


    let jwt = get_jwt_from_api(http_client.clone()).await;
    let mut zip = http_client
        .post(format!("{}/api/sbom-reports/download", &endpoint))
        .cookie(Cookie::new("jwtToken", &jwt))
        .send_json(&etcd.report.artifact)
        .await
        .unwrap();

    let zip = zip.body().await?;

    Ok(())
}