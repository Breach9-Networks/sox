use std::collections::HashMap;

use super::AuthProvider;

/// Username/password authentication provider.
///
/// Stores credentials in memory. For production use with many users,
/// consider a more sophisticated backend.
pub struct PasswordAuth {
    users: HashMap<String, String>,
}

impl PasswordAuth {
    pub fn new(users: Vec<(String, String)>) -> Self {
        Self {
            users: users.into_iter().collect(),
        }
    }
}

impl AuthProvider for PasswordAuth {
    fn authenticate(&self, username: &str, password: &str) -> bool {
        self.users
            .get(username)
            .is_some_and(|stored| constant_time_eq(stored.as_bytes(), password.as_bytes()))
    }
}

/// Constant-time byte comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_credentials() {
        let auth = PasswordAuth::new(vec![
            ("alice".into(), "secret".into()),
            ("bob".into(), "hunter2".into()),
        ]);
        assert!(auth.authenticate("alice", "secret"));
        assert!(auth.authenticate("bob", "hunter2"));
    }

    #[test]
    fn invalid_credentials() {
        let auth = PasswordAuth::new(vec![("alice".into(), "secret".into())]);
        assert!(!auth.authenticate("alice", "wrong"));
        assert!(!auth.authenticate("eve", "secret"));
        assert!(!auth.authenticate("", ""));
    }

    #[test]
    fn test_empty_password() {
        let auth = PasswordAuth::new(vec![("user".into(), "".into())]);
        assert!(auth.authenticate("user", ""));
        assert!(!auth.authenticate("user", "notempty"));
    }
}
