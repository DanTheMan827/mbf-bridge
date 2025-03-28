pub mod router_instance;

use crate::{adb::adb_connect_or_start, eprint_message};
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Handles incoming websocket connections and proxies data to/from the ADB server.
pub async fn handle_websocket(ws: WebSocket) {
    let (mut ws_writer, mut ws_reader) = ws.split();

    // Connect to (or start) ADB and split the connection.
    let adb_conn = match adb_connect_or_start().await {
        Ok(conn) => conn,
        Err(e) => {
            eprint_message(format!("Failed to connect to ADB: {:?}", e).as_str());
            return;
        }
    };

    let (mut adb_reader, mut adb_writer) = adb_conn.into_split();

    // Run both directions concurrently.
    tokio::join!(
        async {
            // Forward binary messages from the websocket to ADB.
            while let Some(msg) = ws_reader.next().await {
                match msg {
                    Ok(Message::Binary(packet)) => {
                        if let Err(e) = adb_writer.write_all(&packet).await {
                            eprint_message(format!("Error writing to ADB: {:?}", e).as_str());
                            break;
                        }
                    }
                    Ok(_) => {
                        // Ignore non-binary messages.
                    }
                    Err(e) => {
                        eprint_message(format!("Error reading from websocket: {:?}", e).as_str());
                        break;
                    }
                }
            }
            if let Err(e) = adb_writer.shutdown().await {
                eprint_message(format!("Error shutting down ADB writer: {:?}", e).as_str());
            }
        },
        async {
            // Read data from ADB and send as binary messages over the websocket.
            let mut buf = vec![0; 1024 * 1024];
            loop {
                match adb_reader.read(&mut buf).await {
                    Ok(0) => {
                        if let Err(e) = ws_writer.close().await {
                            eprint_message(format!("Error closing websocket: {:?}", e).as_str());
                        }
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = ws_writer
                            .send(Message::binary(buf[..n].to_vec()))
                            .await
                        {
                            eprint_message(format!("Error sending message on websocket: {:?}", e).as_str());
                            break;
                        }
                    }
                    Err(e) => {
                        eprint_message(format!("Error reading from ADB: {:?}", e).as_str());
                        if let Err(e) = ws_writer.close().await {
                            eprint_message(format!("Error closing websocket: {:?}", e).as_str());
                        }
                        break;
                    }
                }
            }
        }
    );
}
