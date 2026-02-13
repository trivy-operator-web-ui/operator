use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Eq, PartialEq, Hash, Serialize, Deserialize, Clone, Debug)]
pub struct Workload {
    pub kind: String,
    pub namespace: String,
    pub name: String,
}

impl Workload {
    pub fn new(labels: BTreeMap<String, String>) -> Workload {
        let kind = labels.get("trivy-operator.resource.kind").cloned().unwrap();

        let namespace = labels
            .get("trivy-operator.resource.namespace")
            .cloned()
            .unwrap();

        let name = labels.get("trivy-operator.resource.name").cloned().unwrap();

        Workload {
            kind,
            namespace,
            name,
        }
    }
}
