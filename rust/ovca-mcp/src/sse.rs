/// SSE broadcast channel for real-time event streaming.
use axum::response::sse::Event;
use std::convert::Infallible;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

pub const SSE_CHANNEL_CAPACITY: usize = 256;

pub fn make_sse_channel() -> (broadcast::Sender<String>, broadcast::Receiver<String>) {
    broadcast::channel::<String>(SSE_CHANNEL_CAPACITY)
}

/// Convert a broadcast receiver into an Axum SSE stream.
/// Lagged messages are silently dropped via BroadcastStream's handling.
pub fn broadcast_to_sse_stream(
    rx: broadcast::Receiver<String>,
) -> impl futures_util::Stream<Item = Result<Event, Infallible>> {
    BroadcastStream::new(rx).filter_map(
        |msg: Result<String, tokio_stream::wrappers::errors::BroadcastStreamRecvError>| {
            msg.ok().map(|data| Ok(Event::default().data(data)))
        },
    )
}
