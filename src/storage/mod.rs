//! Storage module for WeCom message caching
//!
//! Provides SQLite-based local storage for:
//! - KF message deduplication
//! - Sync state persistence (cursor-based recovery)
//! - Conversation state tracking

mod models;
mod sqlite;

#[allow(unused_imports)]
pub use models::{KfConversation, KfMessage, KfSyncState};
pub use sqlite::MessageStore;
