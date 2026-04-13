import { useEffect, useState } from "react";
import { AdbServerClient } from "@yume-chan/adb";
import { MbfAdbServerConnector } from "../connector/MbfAdbServerConnector";

export type ScannerStatus = "idle" | "connecting" | "tracking" | "error";

export interface DeviceScannerState {
  devices: AdbServerClient.Device[];
  status: ScannerStatus;
  error: string | null;
}

/**
 * Subscribes to a live ADB device list via `AdbServerClient.trackDevices()`,
 * using the `MbfAdbServerConnector` to route connections through the Tauri
 * IPC bridge.
 *
 * The observer is automatically torn down when the component unmounts.
 */
export function useDeviceScanner(enabled: boolean): DeviceScannerState {
  const [devices, setDevices] = useState<AdbServerClient.Device[]>([]);
  const [status, setStatus] = useState<ScannerStatus>("idle");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) {
      setStatus("idle");
      setDevices([]);
      setError(null);
      return;
    }

    let cancelled = false;
    // Local variable captured by both the async setup and the cleanup closure.
    let observer: AdbServerClient.DeviceObserver | null = null;

    setStatus("connecting");
    setError(null);

    const client = new AdbServerClient(new MbfAdbServerConnector());

    void (async () => {
      try {
        const obs = await client.trackDevices();

        if (cancelled) {
          obs.stop();
          return;
        }

        observer = obs;

        // Seed with the initial device list.
        setDevices([...obs.current]);
        setStatus("tracking");

        // Subscribe to future list changes.
        obs.onListChange((list) => setDevices([...list]));

        // Surface ADB server errors.
        obs.onError((e) => {
          setError(e.message);
          setStatus("error");
        });
      } catch (e: unknown) {
        if (!cancelled) {
          setError((e as Error).message ?? String(e));
          setStatus("error");
        }
      }
    })();

    return () => {
      cancelled = true;
      observer?.stop();
      setDevices([]);
      setStatus("idle");
    };
  }, [enabled]);

  return { devices, status, error };
}
