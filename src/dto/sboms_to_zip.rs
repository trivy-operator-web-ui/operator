use crate::kube_types::Artifact;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Serialize, Deserialize)]
pub struct SbomsToZip {
    pub artifacts: HashSet<Artifact>,
}