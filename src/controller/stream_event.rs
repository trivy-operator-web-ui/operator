use crate::kube_types::{SbomReport, VulnerabilityReport};
use kube::runtime::watcher::Event;

pub enum StreamEvent {
    VulnerabilityReport(Event<VulnerabilityReport>),
    SbomReport(Event<SbomReport>),
}
