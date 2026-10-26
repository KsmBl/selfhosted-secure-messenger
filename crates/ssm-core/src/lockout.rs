//! Delay policy after failed unlock attempts (ADR-0005).
//!
//! This only slows down guessing on the device itself; it does not protect a
//! copied container against offline attacks.

use std::time::Duration;

/// Failed attempts that are allowed without any delay.
pub const FREE_ATTEMPTS: u32 = 4;
const BASE_DELAY: Duration = Duration::from_secs(30);
const MAX_DELAY: Duration = Duration::from_secs(60 * 60);

/// Waiting time before the next attempt after `failures` consecutive failures.
pub fn delay_after_failures(failures: u32) -> Duration {
    if failures <= FREE_ATTEMPTS {
        return Duration::ZERO;
    }
    let exponent = (failures - FREE_ATTEMPTS - 1).min(16);
    (BASE_DELAY * 2u32.pow(exponent)).min(MAX_DELAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_exponentially_from_fifth_failure_and_caps() {
        assert_eq!(delay_after_failures(0), Duration::ZERO);
        assert_eq!(delay_after_failures(4), Duration::ZERO);
        assert_eq!(delay_after_failures(5), Duration::from_secs(30));
        assert_eq!(delay_after_failures(6), Duration::from_secs(60));
        assert_eq!(delay_after_failures(10), Duration::from_secs(960));
        assert_eq!(delay_after_failures(12), MAX_DELAY);
        assert_eq!(delay_after_failures(u32::MAX), MAX_DELAY);
    }
}
