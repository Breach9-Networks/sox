pub mod none;
pub mod password;

/// Authentication provider trait.
///
/// Intentionally synchronous — auth is typically a fast in-memory lookup.
/// For async backends (LDAP, database), implementors can use
/// `tokio::task::block_in_place()`.
pub trait AuthProvider: Send + Sync + 'static {
    /// Validate credentials. Returns `true` on success.
    fn authenticate(&self, username: &str, password: &str) -> bool;
}
