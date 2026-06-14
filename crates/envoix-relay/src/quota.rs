//! Monthly byte quota guard (design §4.4).
//!
//! Pure counting and month-rollover logic. The caller supplies the
//! current month as an integer (`year * 12 + month0`), so this type never
//! touches the clock and is fully unit-testable; the binary computes the
//! month from `SystemTime` and persists the snapshot to disk
//! (`/var/lib/envoix-relay/usage.json`) so a restart - or restart loop -
//! cannot bypass the limit.

/// Tracks bytes forwarded in the current month against a hard limit.
pub struct MonthlyUsage {
    month: u32,
    bytes: u64,
    limit: u64,
}

impl MonthlyUsage {
    pub fn new(limit: u64) -> Self {
        Self {
            month: 0,
            bytes: 0,
            limit,
        }
    }

    /// Rehydrate from a persisted snapshot (the binary loads this at
    /// startup; `check` will reset it if the month has since rolled over).
    pub fn with_state(limit: u64, month: u32, bytes: u64) -> Self {
        Self {
            month,
            bytes,
            limit,
        }
    }

    /// Roll over if the month changed, then report whether forwarding is
    /// still permitted (under the limit). Call before forwarding a
    /// datagram; on `false`, drop and count `quota_exceeded`.
    pub fn check(&mut self, now_month: u32) -> bool {
        if now_month != self.month {
            self.month = now_month;
            self.bytes = 0;
        }
        self.bytes < self.limit
    }

    /// Count forwarded payload bytes toward the month. Call after a
    /// successful forward.
    pub fn record(&mut self, bytes: u64) {
        self.bytes = self.bytes.saturating_add(bytes);
    }

    /// `(month, bytes)` for persistence.
    pub fn snapshot(&self) -> (u32, u64) {
        (self.month, self.bytes)
    }

    pub fn month_bytes(&self) -> u64 {
        self.bytes
    }

    pub fn limit(&self) -> u64 {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn under_limit_permits_then_blocks() {
        let mut u = MonthlyUsage::new(1000);
        assert!(u.check(100)); // month 100
        u.record(600);
        assert!(u.check(100)); // 600 < 1000
        u.record(600);
        assert!(!u.check(100)); // 1200 >= 1000 -> blocked
    }

    #[test]
    fn month_rollover_resets() {
        let mut u = MonthlyUsage::new(1000);
        u.check(100);
        u.record(1500); // way over
        assert!(!u.check(100)); // blocked this month
        // New month: counter resets, forwarding permitted again.
        assert!(u.check(101));
        assert_eq!(u.month_bytes(), 0);
    }

    #[test]
    fn persisted_state_survives_restart() {
        let mut u = MonthlyUsage::new(1000);
        u.check(100);
        u.record(800);
        let (month, bytes) = u.snapshot();

        // Simulate restart: rebuild from the snapshot.
        let mut restored = MonthlyUsage::with_state(1000, month, bytes);
        assert!(restored.check(100)); // 800 < 1000, still ok
        restored.record(300);
        assert!(!restored.check(100)); // 1100 >= 1000 - restart didn't reset
    }

    #[test]
    fn saturates_without_overflow() {
        let mut u = MonthlyUsage::new(u64::MAX);
        u.check(1);
        u.record(u64::MAX);
        u.record(u64::MAX); // must not panic
        assert_eq!(u.month_bytes(), u64::MAX);
    }
}
