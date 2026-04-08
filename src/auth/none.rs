use super::AuthProvider;

/// Accepts all connections without authentication.
pub struct NoAuth;

impl AuthProvider for NoAuth {
    fn authenticate(&self, _username: &str, _password: &str) -> bool {
        true
    }
}
