use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;

use crate::dto::Workload;
use crate::kube_types::Artifact;

#[derive(Clone, Default)]
pub struct SharedState<T> {
    pub reports: Arc<Mutex<HashMap<Artifact, T>>>,
    pub owners: Arc<Mutex<HashMap<Artifact, HashSet<Workload>>>>,
}
