use crate::api::dto::Credentials;

#[derive(Clone)]
pub struct UserService {
    username: String,
    password: String,
}

impl UserService {
    pub fn new(username: String, password: String) -> UserService {
        UserService { username, password }
    }

    pub fn check_credentials(&self, credentials: &Credentials) -> bool {
        self.username == credentials.username && self.password == credentials.password
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use crate::api::{dto::Credentials, services::UserService};
    use crate::common_test_utils::{TEST_PASSWORD, TEST_USERNAME};

    #[test]
    fn right_credentials() -> Result<()> {
        let user_service = UserService::new(TEST_USERNAME.to_string(), TEST_PASSWORD.to_string());
        let credentials = Credentials {
            username: TEST_USERNAME.to_string(),
            password: TEST_PASSWORD.to_string(),
        };

        assert!(user_service.check_credentials(&credentials));

        Ok(())
    }

    #[test]
    fn wrong_credentials() -> Result<()> {
        let user_service = UserService::new(TEST_USERNAME.to_string(), TEST_PASSWORD.to_string());
        let credentials = Credentials {
            username: "dummy".to_string(),
            password: TEST_PASSWORD.to_string(),
        };

        assert!(!user_service.check_credentials(&credentials));

        let credentials = Credentials {
            username: TEST_USERNAME.to_string(),
            password: "dummy".to_string(),
        };
        assert!(!user_service.check_credentials(&credentials));

        let credentials = Credentials {
            username: "dummy".to_string(),
            password: "dummy".to_string(),
        };
        assert!(!user_service.check_credentials(&credentials));

        Ok(())
    }
}
