use anyhow::{Error, Result};
use kube::{
    Api, Client,
    api::{DeleteParams, DynamicObject, GroupVersionKind, ListParams, PostParams},
};
use std::{fs, sync::LazyLock, time::Duration};
use tokio::time::sleep;

use crate::{
    api::dto::Credentials,
    kube_types::{ExposedSecretReport, SbomReport, VulnerabilityReport},
};

pub const ROOT_FOLDER_TEST_ASSESTS: &str = "test_assets";
pub const VULNERABILITY_REPORT_FOLDER: &str = "vulnerability_reports";
pub const SBOM_REPORT_FOLDER: &str = "sbom_reports";
pub const EXPOSED_SECRET_REPORT_FOLDER: &str = "exposed_secret_reports";

pub const ETCD: &str = "etcd";
pub const RABBIT_ONE: &str = "rabbit-one";
pub const RABBIT_TWO: &str = "rabbit-two";

pub const RESOURCES: [&str; 2] = [ETCD, RABBIT_ONE];
pub const NAMESPACES: [&str; 3] = [ETCD, RABBIT_ONE, RABBIT_TWO];

pub const TEST_USERNAME: &str = "username";
pub const TEST_PASSWORD: &str = "password";

pub const VULNERABILITY_REPORT_GROUP: &str = "aquasecurity.github.io";
pub const VULNERABILITY_REPORT_VERSION: &str = "v1alpha1";
pub const VULNERABILITY_REPORT_KIND: &str = "VulnerabilityReport";

pub const VULNERABILITY_REPORT_GVK: LazyLock<GroupVersionKind> = LazyLock::new(|| {
    GroupVersionKind::gvk(
        VULNERABILITY_REPORT_GROUP,
        VULNERABILITY_REPORT_VERSION,
        VULNERABILITY_REPORT_KIND,
    )
});

pub const SBOM_REPORT_GROUP: &str = "aquasecurity.github.io";
pub const SBOM_REPORT_VERSION: &str = "v1alpha1";
pub const SBOM_REPORT_KIND: &str = "SbomReport";

pub const SBOM_REPORT_GVK: LazyLock<GroupVersionKind> = LazyLock::new(|| {
    GroupVersionKind::gvk(SBOM_REPORT_GROUP, SBOM_REPORT_VERSION, SBOM_REPORT_KIND)
});

pub const EXPOSED_SECRET_REPORT_GROUP: &str = "aquasecurity.github.io";
pub const EXPOSED_SECRET_REPORT_VERSION: &str = "v1alpha1";
pub const EXPOSED_SECRET_REPORT_KIND: &str = "ExposedSecretReport";

pub const EXPOSED_SECRET_REPORT_GVK: LazyLock<GroupVersionKind> = LazyLock::new(|| {
    GroupVersionKind::gvk(
        EXPOSED_SECRET_REPORT_GROUP,
        EXPOSED_SECRET_REPORT_VERSION,
        EXPOSED_SECRET_REPORT_KIND,
    )
});

impl Credentials {
    pub fn new(username: String, password: String) -> Credentials {
        Credentials { username, password }
    }
}

pub fn read_test_vulnerability_report(name: &str) -> Result<VulnerabilityReport> {
    let report: VulnerabilityReport = serde_yaml::from_str(&fs::read_to_string(format!(
        "{}/{}/{}.yaml",
        ROOT_FOLDER_TEST_ASSESTS, VULNERABILITY_REPORT_FOLDER, name,
    ))?)?;

    Ok(report)
}

pub fn read_test_exposed_secret_report(name: &str) -> Result<ExposedSecretReport> {
    let report: ExposedSecretReport = serde_yaml::from_str(&fs::read_to_string(format!(
        "{}/{}/{}.yaml",
        ROOT_FOLDER_TEST_ASSESTS, EXPOSED_SECRET_REPORT_FOLDER, name
    ))?)?;

    Ok(report)
}

pub fn read_test_sbom_report(name: &str) -> Result<SbomReport> {
    let report: SbomReport = serde_yaml::from_str(&fs::read_to_string(format!(
        "{}/{}/{}.yaml",
        ROOT_FOLDER_TEST_ASSESTS, SBOM_REPORT_FOLDER, name
    ))?)?;

    Ok(report)
}

pub async fn apply_test_resource(
    client: Client,
    gvk: GroupVersionKind,
    name: &str,
) -> Result<DynamicObject> {
    let test_resource_folder: Result<&str> = match gvk.kind.as_str() {
        VULNERABILITY_REPORT_KIND => Ok(VULNERABILITY_REPORT_FOLDER),
        SBOM_REPORT_KIND => Ok(SBOM_REPORT_FOLDER),
        EXPOSED_SECRET_REPORT_KIND => Ok(EXPOSED_SECRET_REPORT_FOLDER),
        _ => Err(Error::msg("Unknown GVK to map to a test folder")),
    };

    let report: DynamicObject = serde_yaml::from_str(&fs::read_to_string(format!(
        "{}/{}/{}.yaml",
        ROOT_FOLDER_TEST_ASSESTS,
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

pub async fn delete_test_resource(
    client: Client,
    gvk: GroupVersionKind,
    name: &str,
) -> Result<DynamicObject> {
    let test_resource_folder: Result<&str> = match gvk.kind.as_str() {
        VULNERABILITY_REPORT_KIND => Ok(VULNERABILITY_REPORT_FOLDER),
        SBOM_REPORT_KIND => Ok(SBOM_REPORT_FOLDER),
        EXPOSED_SECRET_REPORT_KIND => Ok(EXPOSED_SECRET_REPORT_FOLDER),
        _ => Err(Error::msg("Unknown GVK to map to a test folder")),
    };

    let report: DynamicObject = serde_yaml::from_str(&fs::read_to_string(format!(
        "{}/{}/{}.yaml",
        ROOT_FOLDER_TEST_ASSESTS,
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

pub async fn cleanup_test_namespace(client: Client) -> Result<()> {
    for namespace in NAMESPACES {
        let vulnerability_report_api: Api<VulnerabilityReport> =
            Api::namespaced(client.clone(), namespace);
        let sbom_report_api: Api<SbomReport> = Api::namespaced(client.clone(), namespace);
        let exposed_secret_report_api: Api<ExposedSecretReport> =
            Api::namespaced(client.clone(), namespace);

        vulnerability_report_api
            .delete_collection(&DeleteParams::default(), &ListParams::default())
            .await?;

        sbom_report_api
            .delete_collection(&DeleteParams::default(), &ListParams::default())
            .await?;

        exposed_secret_report_api
            .delete_collection(&DeleteParams::default(), &ListParams::default())
            .await?;
    }
    Ok(())
}

pub fn get_test_endpoint() -> String {
    std::env::var("TEST_ENDPOINT").unwrap_or("http://localhost:8080".to_string())
}

pub fn get_login_endpoint() -> String {
    format!("{}/{}", get_test_endpoint(), "api/login").to_string()
}

pub async fn get_jwt_from_api(http_client: awc::Client) -> String {
    let login_endpoint = get_login_endpoint();
    let credentials = Credentials::new(TEST_USERNAME.to_string(), TEST_PASSWORD.to_string());

    let res = http_client
        .post(&login_endpoint)
        .send_json(&credentials)
        .await
        .unwrap();

    res.cookie("jwtToken").unwrap().value().to_string()
}
