use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug, Default)]
pub struct Scanner {
    pub name: String,
    pub vendor: String,
    pub version: String,
}
