use crate::kube_types::{ExposedSecretReport, SbomReport, VulnerabilityReport};
use kube::runtime::watcher::Event;

#[allow(clippy::enum_variant_names)]
pub enum StreamEvent {
    VulnerabilityReport(Event<VulnerabilityReport>),
    SbomReport(Event<SbomReport>),
    ExposedSecretReport(Event<ExposedSecretReport>),
}
