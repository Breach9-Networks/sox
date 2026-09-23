use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

/// Per-IP connection limiter.
///
/// Tracks active connection count per source IP and rejects
/// connections that exceed the per-IP limit.
/// Uses `Arc` internally so guards can be moved into `'static` tasks.
#[derive(Clone)]
pub struct PerIpLimiter {
    max_per_ip: usize,
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

impl PerIpLimiter {
    pub fn new(max_per_ip: usize) -> Self {
        Self {
            max_per_ip,
            counts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Try to acquire a slot for the given IP.
    /// Returns an owned guard that releases the slot on drop.
    pub fn try_acquire(&self, ip: IpAddr) -> Option<PerIpGuard> {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let count = counts.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return None;
        }
        *count += 1;
        Some(PerIpGuard {
            counts: self.counts.clone(),
            ip,
        })
    }
}

impl PerIpLimiter {
    /// Top `n` source IPs by active connection count (for the dashboard) —
    /// read straight from the limiter, the single source of per-IP truth.
    pub fn top(&self, n: usize) -> Vec<crate::server::extended_metrics::IpCount> {
        let counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let mut top: Vec<_> = counts
            .iter()
            .map(|(ip, count)| crate::server::extended_metrics::IpCount {
                ip: ip.to_string(),
                connections: *count as u64,
            })
            .collect();
        top.sort_by_key(|c| std::cmp::Reverse(c.connections));
        top.truncate(n);
        top
    }
}

/// Owned guard — safe to move into `tokio::spawn` tasks.
pub struct PerIpGuard {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for PerIpGuard {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = counts.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

/// Check and attempt to raise the system file descriptor limit.
/// Returns the effective soft limit.
pub fn check_fd_limit() -> std::io::Result<u64> {
    #[cfg(unix)]
    {
        use std::io;

        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };

        // Safety: getrlimit is a standard POSIX syscall with valid pointer
        let ret = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        let soft = rlim.rlim_cur;
        let hard = rlim.rlim_max;

        tracing::info!(soft, hard, "file descriptor limits");

        // Try to raise soft to hard
        if soft < hard {
            rlim.rlim_cur = hard;
            // Safety: setrlimit is a standard POSIX syscall with valid pointer
            let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) };
            if ret == 0 {
                tracing::info!(new_soft = hard, "raised FD soft limit");
                return Ok(hard);
            }
            tracing::warn!("failed to raise FD soft limit");
        }

        Ok(soft)
    }

    #[cfg(not(unix))]
    {
        tracing::info!("FD limit check skipped on non-Unix platform");
        Ok(u64::MAX)
    }
}
