//! Storage module for WeCom message caching
//!
//! Provides SQLite-based local storage for:
//! - KF message deduplication

mod models;
mod sqlite;

pub use models::KfMessage;
pub use sqlite::MessageStore;
