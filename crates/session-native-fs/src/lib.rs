//! Narrow native filesystem controls used by local-app security boundaries.
#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use windows::{create_owner_only_file, open_owner_only_regular_file, verify_owner_only_file};
