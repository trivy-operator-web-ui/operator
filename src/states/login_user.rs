#[derive(Clone)]
pub struct LoginUserState {
    pub username: String,
    pub password: String,
}

impl LoginUserState {
    pub fn new(username: String, password: String) -> LoginUserState {
        LoginUserState { username, password }
    }
}
