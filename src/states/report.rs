use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;

use crate::kube_types::Artifact;
use crate::kube_types::Workload;

#[derive(Clone, Default)]
pub struct ReportState<T> {
    pub reports: Arc<Mutex<HashMap<Artifact, T>>>,
    pub owners: Arc<Mutex<HashMap<Artifact, HashSet<Workload>>>>,
}
