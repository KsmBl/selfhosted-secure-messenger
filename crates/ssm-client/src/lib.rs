//! Device client shared by the Linux app and (through ssm-ffi) Android.

pub mod api;
pub mod client;
pub mod content;
pub mod error;
pub mod profile;
pub mod realtime;

pub use client::{Client, EnrollWith, LockedClient, UnlockFailed, Update};
pub use content::{Content, DisplayBody, DisplayMessage};
pub use error::{ClientError, ClientResult};
pub use realtime::{Wake, WakeChannel};
