import { useEffect, useRef, useState } from "react";
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
  // Stable ref so the cleanup closure always has the latest observer.
  const observerRef = useRef<AdbServerClient.DeviceObserver | null>(null);

  useEffect(() => {
    if (!enabled) {
      setStatus("idle");
      setDevices([]);
      setError(null);
      return;
    }

    let cancelled = false;

    setStatus("connecting");
    setError(null);

    const client = new AdbServerClient(new MbfAdbServerConnector());

    void (async () => {
      try {
        const observer = await client.trackDevices();

        if (cancelled) {
          observer.stop();
          return;
        }

        observerRef.current = observer;

        // Seed with the initial device list.
        setDevices([...observer.current]);
        setStatus("tracking");

        // Subscribe to future list changes.
        observer.onListChange((list) => setDevices([...list]));

        // Surface ADB server errors.
        observer.onError((e) => {
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
      observerRef.current?.stop();
      observerRef.current = null;
      setDevices([]);
      setStatus("idle");
    };
  }, [enabled]);

  return { devices, status, error };
}
