pub mod proxy_request_handler;
pub mod router_instance;

use std::{future::Future, pin::Pin, sync::OnceLock};

use crate::adb::adb_connect_or_start;
use axum::{
    extract::{
        ws::{Message, WebSocket}, Request
    }, response::{IntoResponse, Response}
};
use futures_util::{SinkExt, StreamExt};
use reqwest::{Url, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Handles incoming websocket connections and proxies data to/from the ADB server.
pub async fn handle_websocket(ws: WebSocket) {
    let (mut ws_writer, mut ws_reader) = ws.split();

    // Connect to (or start) ADB and split the connection.
    let (mut adb_reader, mut adb_writer) = adb_connect_or_start().await.unwrap().into_split();

    // Run both directions concurrently.
    tokio::join!(
        async {
            // Forward binary messages from the websocket to ADB.
            while let Some(Ok(message)) = ws_reader.next().await {
                if let Message::Binary(packet) = message {
                    adb_writer.write_all(&packet).await.unwrap();
                }
            }
            adb_writer.shutdown().await.unwrap();
        },
        async {
            // Read data from ADB and send as binary messages over the websocket.
            let mut buf = vec![0; 1024 * 1024];
            loop {
                match adb_reader.read(&mut buf).await {
                    Ok(0) | Err(_) => {
                        ws_writer.close().await.unwrap();
                        break;
                    }
                    Ok(n) => {
                        ws_writer
                            .send(Message::binary(buf[..n].to_vec()))
                            .await
                            .unwrap();
                    }
                }
            }
        }
    );
}
