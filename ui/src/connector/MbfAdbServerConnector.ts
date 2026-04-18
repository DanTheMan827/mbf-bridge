/**
 * Implements {@link AdbServerClient.ServerConnector} over the
 * `window.__mbfBridge` API, routing each ADB host-protocol connection
 * through the Tauri IPC bridge.
 *
 * Based on MbfAdbServerConnector.ts from the ModsBeforeFriday project
 * (https://github.com/DanTheMan827/ModsBeforeFriday).
 */

import { AdbServerClient } from "@yume-chan/adb";
import { PromiseResolver } from "@yume-chan/async";
import {
  MaybeConsumable,
  type ReadableStream as ExtraReadableStream,
} from "@yume-chan/stream-extra";

export class MbfAdbServerConnector
  implements AdbServerClient.ServerConnector
{
  async connect(): Promise<AdbServerClient.ServerConnection> {
    if (!window.__mbfBridge?.isAdbAvailable) {
      throw new Error("ADB bridge is not available");
    }

    const conn = await window.__mbfBridge.connect();

    const closed = new PromiseResolver<undefined>();
    let closedResolved = false;

    const resolveClosed = (): void => {
      if (!closedResolved) {
        closedResolved = true;
        conn.close().catch(() => {
          // Swallow close errors — the connection is already considered gone.
        });
        closed.resolve(undefined);
      }
    };

    conn.onClose(resolveClosed);

    // Each chunk enqueued by onData is forwarded into the readable stream.
    const readable = new ReadableStream<Uint8Array>({
      start(controller) {
        conn.onData((chunk) => controller.enqueue(chunk));
        // Close the readable when the underlying bridge connection closes.
        closed.promise.then(() => {
          try {
            controller.close();
          } catch {
            // Already closed — ignore.
          }
        });
      },
      cancel() {
        resolveClosed();
      },
    }) as unknown as ExtraReadableStream<Uint8Array>;

    // MaybeConsumable.WritableStream internally calls tryConsume, so the
    // sink's write() receives a plain Uint8Array (already unwrapped).
    const writable = new MaybeConsumable.WritableStream<Uint8Array>({
      write(chunk): Promise<void> {
        if (closedResolved) {
          throw new Error("Cannot write to a closed connection");
        }
        return conn.write(chunk).then(() => undefined);
      },
      close() {
        resolveClosed();
      },
      abort() {
        resolveClosed();
      },
    });

    return {
      readable,
      writable,
      get closed() {
        return closed.promise;
      },
      close: async () => resolveClosed(),
    };
  }

  addReverseTunnel(): never {
    throw new Error(
      "Reverse tunnels are not supported by MbfAdbServerConnector",
    );
  }

  removeReverseTunnel(): never {
    throw new Error(
      "Reverse tunnels are not supported by MbfAdbServerConnector",
    );
  }

  clearReverseTunnels(): never {
    throw new Error(
      "Reverse tunnels are not supported by MbfAdbServerConnector",
    );
  }
}
