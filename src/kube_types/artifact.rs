// Data type shared by both reports

use std::fmt::{Display, Formatter, Result};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, Default, Eq, PartialEq, Hash, JsonSchema)]
pub struct Artifact {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "mimeType")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

impl Display for Artifact {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let mut buffer = String::new();

        if let Some(repository) = &self.repository {
            buffer.push_str(repository);
        }

        if let Some(tag) = &self.tag {
            buffer.push_str(&format!(":{}", &tag));
        }

        if let Some(digest) = &self.digest {
            buffer.push_str(&format!("@{}", &digest[..15]));
        }

        write!(f, "{}", buffer)
    }
}
