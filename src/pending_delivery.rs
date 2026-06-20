//! Pending-delivery buffer for messages that arrive while no UGENT client is
//! connected (or the connected client's broadcast failed).
//!
//! Closes the "message lost while the worker was stranded" gap: a WeCom message
//! that lands during a stranded window used to be permanently lost, because the
//! dedup cache already committed its msgid and WeCom's sync cursor advanced past
//! it. Now such messages are held per channel and replayed to the reconnecting
//! client.
//!
//! Bounded and in-memory. A client that never reconnects cannot grow the buffer
//! unbounded (oldest entries are dropped with a warning). Crash-safe persistence
//! is a deferred follow-up — see plan 2026-06-20-001 U3.

use std::collections::VecDeque;
use std::sync::Mutex;

use dashmap::DashMap;
use tracing::{info, warn};

use crate::types::ProxyMessage;

/// Default cap on buffered messages per channel.
const DEFAULT_MAX_PER_CHANNEL: usize = 256;

/// Per-channel pending message queue (bounded).
///
/// Keyed by channel tag (`"wecom"` / `"wechat"`) rather than client id, because a
/// message is buffered precisely when *no* client is connected, so no client id is
/// known. Replay is triggered by [`WebSocketManager`](crate::ws_manager) when a
/// client authenticates for that channel (see [`drain_for_client`]).
#[derive(Debug)]
pub struct PendingDeliveryQueue {
    queues: DashMap<String, Mutex<VecDeque<ProxyMessage>>>,
    max_per_channel: usize,
}

impl Default for PendingDeliveryQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingDeliveryQueue {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_PER_CHANNEL)
    }

    pub fn with_capacity(max_per_channel: usize) -> Self {
        Self {
            queues: DashMap::new(),
            max_per_channel: max_per_channel.max(1),
        }
    }

    /// Enqueue a message for a channel. When the per-channel buffer is full the
    /// oldest entry is dropped (with a warning) so the newest messages survive.
    pub fn enqueue(&self, channel_tag: &str, msg: ProxyMessage) {
        let entry = self
            .queues
            .entry(channel_tag.to_string())
            .or_insert_with(|| Mutex::new(VecDeque::with_capacity(self.max_per_channel)));
        // Lock ordering is consistent (DashMap shard ref before the inner Mutex, never
        // the reverse), so this cannot deadlock.
        let mut guard = entry.lock().unwrap_or_else(|p| p.into_inner());
        while guard.len() >= self.max_per_channel {
            let _dropped = guard.pop_front();
            warn!(
                "pending-delivery buffer for '{}' full (cap {}), dropped oldest message",
                channel_tag, self.max_per_channel
            );
        }
        guard.push_back(msg);
    }

    /// Drain all pending messages for a channel in insertion order. Removes the
    /// channel's slot. Returns an empty vec if nothing was buffered.
    pub fn drain(&self, channel_tag: &str) -> Vec<ProxyMessage> {
        match self.queues.remove(channel_tag) {
            Some((_, queue)) => Self::take_all(queue),
            None => Vec::new(),
        }
    }

    /// Drain the pending buffer for whichever channel a reconnecting client
    /// serves, mirroring [`WebSocketManager`](crate::ws_manager)'s client-id →
    /// channel detection. Returns an empty vec for unknown channels.
    pub fn drain_for_client(&self, client_id: &str) -> Vec<ProxyMessage> {
        match Self::channel_tag_for_client(client_id) {
            Some(tag) => {
                let drained = self.drain(tag);
                if !drained.is_empty() {
                    info!(
                        "Replaying {} buffered message(s) to reconnecting client {}",
                        drained.len(),
                        client_id
                    );
                }
                drained
            }
            None => Vec::new(),
        }
    }

    /// Map a client id to its channel tag, matching ws_manager's detection.
    fn channel_tag_for_client(client_id: &str) -> Option<&'static str> {
        let cid = client_id.to_lowercase();
        if cid.contains("wecom") || cid.contains("wechat-work") || cid.contains("wx-work") {
            Some("wecom")
        } else if cid.contains("wechat") {
            Some("wechat")
        } else {
            None
        }
    }

    fn take_all(queue: Mutex<VecDeque<ProxyMessage>>) -> Vec<ProxyMessage> {
        match queue.lock() {
            Ok(mut g) => g.drain(..).collect(),
            Err(p) => p.into_inner().drain(..).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Channel, Direction, ProxyMessage};
    use chrono::Utc;
    use uuid::Uuid;

    /// Build a ProxyMessage whose `client_id` carries the ordering marker. We construct
    /// the struct directly (rather than via `wecom_inbound`) so the tests don't depend
    /// on `WecomMessage` construction details — the queue only cares that it stores
    /// and replays `ProxyMessage` values in order.
    fn sample_msg(marker: &str) -> ProxyMessage {
        ProxyMessage {
            id: Uuid::new_v4(),
            channel: Channel::Wecom,
            timestamp: Utc::now(),
            direction: Direction::Inbound,
            client_id: marker.to_string(),
            wechat_message: None,
            wecom_message: None,
            raw_xml: None,
            media_content: None,
            response: None,
            error: None,
        }
    }
    #[test]
    fn enqueue_then_drain_preserves_order() {
        let q = PendingDeliveryQueue::new();
        q.enqueue("wecom", sample_msg("a"));
        q.enqueue("wecom", sample_msg("b"));
        q.enqueue("wecom", sample_msg("c"));

        let drained = q.drain("wecom");
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].client_id, "a");
        assert_eq!(drained[2].client_id, "c");
        // drain empties the slot
        assert!(q.drain("wecom").is_empty());
    }

    #[test]
    fn drain_for_unknown_channel_is_empty() {
        let q = PendingDeliveryQueue::new();
        assert!(q.drain("never-buffered").is_empty());
    }

    #[test]
    fn overflow_drops_oldest_and_keeps_newest() {
        let q = PendingDeliveryQueue::with_capacity(2);
        q.enqueue("wecom", sample_msg("a"));
        q.enqueue("wecom", sample_msg("b"));
        q.enqueue("wecom", sample_msg("c")); // overflows, drops "a"
        let drained = q.drain("wecom");
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].client_id, "b");
        assert_eq!(drained[1].client_id, "c");
    }

    #[test]
    fn drain_for_client_matches_wecom_tag() {
        let q = PendingDeliveryQueue::new();
        q.enqueue("wecom", sample_msg("x"));
        let drained = q.drain_for_client("ugent-wecom");
        assert_eq!(drained.len(), 1);
        // wechat tag is distinct
        q.enqueue("wechat", sample_msg("y"));
        assert!(q.drain_for_client("ugent-wecom").is_empty());
        let drained2 = q.drain_for_client("ugent-wechat");
        assert_eq!(drained2.len(), 1);
    }

    #[test]
    fn unknown_client_id_drains_nothing() {
        let q = PendingDeliveryQueue::new();
        q.enqueue("wecom", sample_msg("z"));
        assert!(q.drain_for_client("some-other-client").is_empty());
        // buffer is untouched — the real wecom client still drains it
        assert_eq!(q.drain_for_client("ugent-wecom").len(), 1);
    }

    #[test]
    fn channels_are_isolated() {
        let q = PendingDeliveryQueue::new();
        q.enqueue("wecom", sample_msg("w"));
        q.enqueue("wechat", sample_msg("wc"));
        assert_eq!(q.drain("wecom").len(), 1);
        assert_eq!(q.drain("wechat").len(), 1);
    }

    #[test]
    fn channel_tag_detection() {
        assert_eq!(
            PendingDeliveryQueue::channel_tag_for_client("ugent-wecom"),
            Some("wecom")
        );
        assert_eq!(
            PendingDeliveryQueue::channel_tag_for_client("ugent-wechat-work"),
            Some("wecom")
        );
        assert_eq!(
            PendingDeliveryQueue::channel_tag_for_client("ugent-wechat"),
            Some("wechat")
        );
        assert_eq!(
            PendingDeliveryQueue::channel_tag_for_client("random-id"),
            None
        );
    }

    // Compile-time sanity: ProxyMessage carries a channel.
    #[test]
    fn proxy_message_has_wecom_channel() {
        let msg = sample_msg("a");
        assert_eq!(msg.channel, Channel::Wecom);
    }
}
