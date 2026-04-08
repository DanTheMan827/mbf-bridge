pub mod router_instance;

use crate::adb::adb_connect_or_start;
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
            eprintln!("Failed to connect to ADB: {:?}", e);
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
                            eprintln!("Error writing to ADB: {:?}", e);
                            break;
                        }
                    }
                    Ok(_) => {
                        // Ignore non-binary messages.
                    }
                    Err(e) => {
                        eprintln!("Error reading from websocket: {:?}", e);
                        break;
                    }
                }
            }
            if let Err(e) = adb_writer.shutdown().await {
                eprintln!("Error shutting down ADB writer: {:?}", e);
            }
        },
        async {
            // Read data from ADB and send as binary messages over the websocket.
            let mut buf = vec![0; 1024 * 1024];
            loop {
                match adb_reader.read(&mut buf).await {
                    Ok(0) => {
                        if let Err(e) = ws_writer.close().await {
                            eprintln!("Error closing websocket: {:?}", e);
                        }
                        break;
                    }
                    Ok(n) => {
                        if let Err(e) = ws_writer
                            .send(Message::binary(buf[..n].to_vec()))
                            .await
                        {
                            eprintln!("Error sending message on websocket: {:?}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Error reading from ADB: {:?}", e);
                        if let Err(e) = ws_writer.close().await {
                            eprintln!("Error closing websocket: {:?}", e);
                        }
                        break;
                    }
                }
            }
        }
    );
}
