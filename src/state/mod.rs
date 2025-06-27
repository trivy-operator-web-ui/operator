use crate::kubedata::VulnerabilityReport;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Clone, Default)]
pub struct State {
    pub vulnerability_reports: Arc<Mutex<Vec<VulnerabilityReport>>>, // Mutex is necessary to mutate safely across threads
}
