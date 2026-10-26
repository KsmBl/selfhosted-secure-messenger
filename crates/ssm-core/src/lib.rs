//! Shared client core: unlock pattern, local key container and lockout policy.

pub mod container;
pub mod e2ee;
pub mod lockout;
pub mod pattern;

pub use container::{ContainerError, HardwareSecret, KdfParams, UnlockedContainer};
pub use pattern::{Pattern, PatternError};
