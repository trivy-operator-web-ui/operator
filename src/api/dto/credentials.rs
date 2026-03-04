use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}
