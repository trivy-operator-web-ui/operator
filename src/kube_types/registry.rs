use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct Registry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}
