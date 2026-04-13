import {
  useCallback,
  useEffect,
  useState,
} from "react";
import type { AdbServerClient } from "@yume-chan/adb";
import type { AdbConnection } from "../types/global";
import { useLog, type LogClass } from "../hooks/useLog";
import { useDeviceScanner } from "../hooks/useDeviceScanner";
import shared from "../styles/shared.module.css";
import styles from "./TestPage.module.css";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const enc = new TextEncoder();
const dec = new TextDecoder();

function bytesToHex(buf: Uint8Array): string {
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ");
}

function hexDump(buf: Uint8Array): string {
  const MAX = 64;
  const slice = buf.slice(0, MAX);
  let hex = bytesToHex(slice);
  if (buf.length > MAX) hex += ` … (${buf.length} bytes total)`;
  return hex;
}

function adbMsg(body: string): Uint8Array {
  const len = body.length.toString(16).padStart(4, "0").toUpperCase();
  return enc.encode(len + body);
}

function readUntil(
  conn: AdbConnection,
  pred: (buf: Uint8Array) => boolean,
  timeout = 5000,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    let buf = new Uint8Array(0);
    const timer = setTimeout(() => {
      unlisten();
      reject(new Error("Timeout waiting for ADB response"));
    }, timeout);

    const unlisten = conn.onData((chunk) => {
      const merged = new Uint8Array(buf.length + chunk.length);
      merged.set(buf);
      merged.set(chunk, buf.length);
      buf = merged;
      if (pred(buf)) {
        clearTimeout(timer);
        unlisten();
        resolve(buf);
      }
    });
  });
}

async function adbRequest(
  conn: AdbConnection,
  service: string,
  onLog: (cls: LogClass, msg: string) => void,
): Promise<Uint8Array> {
  const msg = adbMsg(service);
  onLog("tx", `→ [${service}] ${hexDump(msg)}`);

  const headerPromise = readUntil(conn, (b) => b.length >= 8);
  await conn.write(msg);

  let resp = await headerPromise;
  const status = dec.decode(resp.slice(0, 4));
  if (status !== "OKAY") {
    throw new Error(`ADB replied: ${status} – ${dec.decode(resp.slice(4))}`);
  }
  const dataLen = parseInt(dec.decode(resp.slice(4, 8)), 16);

  const needed = 8 + dataLen - resp.length;
  if (needed > 0) {
    const more = await readUntil(conn, (b) => b.length >= needed);
    const combined = new Uint8Array(resp.length + more.length);
    combined.set(resp);
    combined.set(more, resp.length);
    resp = combined;
  }
  return resp.slice(8, 8 + dataLen);
}

// ---------------------------------------------------------------------------
// FlowMeter sub-component
// ---------------------------------------------------------------------------

const WINDOW_SIZE = 8;

interface FlowMeterProps {
  inFlight: number;
}

function FlowMeter({ inFlight }: FlowMeterProps) {
  return (
    <div className={styles.flowMeter}>
      <div className={styles.flowMeterRow}>
        {Array.from({ length: WINDOW_SIZE }, (_, i) => (
          <div
            key={i}
            className={styles.bar}
            data-active={String(i < inFlight)}
          />
        ))}
      </div>
      <div className={styles.flowMeterLabel}>
        In-flight: {inFlight} / {WINDOW_SIZE}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// LogPane sub-component
// ---------------------------------------------------------------------------

interface LogPaneProps {
  entries: { id: number; ts: string; cls: string; msg: string }[];
}

function LogPane({ entries }: LogPaneProps) {
  // Entries are rendered newest-first inside a flex column-reverse container,
  // which keeps the latest entry visible at the bottom without any JS scrolling.
  return (
    <div className={shared.log}>
      {[...entries].reverse().map((e) => (
        <div key={e.id}>
          <span className={shared.ts}>[{e.ts}] </span>
          <span className={shared[e.cls]}>{e.msg}</span>
        </div>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// DevicesCard sub-component
// ---------------------------------------------------------------------------

const STATE_CONFIG: Record<
  AdbServerClient.ConnectionState,
  { label: string }
> = {
  device:       { label: "Online"       },
  unauthorized: { label: "Unauthorized" },
  offline:      { label: "Offline"      },
};

interface DevicesCardProps {
  enabled: boolean;
}

function DevicesCard({ enabled }: DevicesCardProps) {
  const { devices, status, error } = useDeviceScanner(enabled);

  return (
    <div className={shared.card}>
      <div className={`${shared.cardHeader} ${styles.devicesHeader}`}>
        <span className={`${shared.cardTitle} ${styles.cardTitleFlex}`}>
          Live Devices
        </span>
        <span className={styles.trackingBadge} data-status={status}>
          {status === "tracking" ? "Tracking"
            : status === "connecting" ? "Connecting…"
            : status === "error" ? "Error"
            : "Idle"}
        </span>
      </div>
      <div className={shared.cardBody}>
        {error && <div className={styles.deviceError}>{error}</div>}

        {devices.length === 0 ? (
          <div className={styles.deviceEmpty}>
            {status === "tracking"
              ? "No devices connected."
              : "Waiting for ADB server…"}
          </div>
        ) : (
          <div className={styles.deviceList}>
            {devices.map((d) => (
              <div
                key={String(d.transportId)}
                className={styles.deviceRow}
              >
                {/* Status dot */}
                <div
                  className={styles.deviceDot}
                  data-state={d.state}
                  title={STATE_CONFIG[d.state as AdbServerClient.ConnectionState]?.label ?? d.state}
                />

                {/* Device info */}
                <div className={styles.deviceInfo}>
                  <div className={styles.deviceSerial} title={d.serial}>
                    {d.serial}
                  </div>
                  <div className={styles.deviceMeta}>
                    {[d.model, d.product, d.device].filter(Boolean).join(" · ") || "—"}
                    {" · "}
                    <span className={styles.mono}>
                      transport_id:{String(d.transportId)}
                    </span>
                  </div>
                </div>

                {/* State badge */}
                <span
                  className={styles.deviceStateBadge}
                  data-state={d.state}
                >
                  {STATE_CONFIG[d.state as AdbServerClient.ConnectionState]?.label ?? d.state}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// TestPage
// ---------------------------------------------------------------------------

interface ConnEntry {
  conn: AdbConnection;
  open: boolean;
}

export default function TestPage() {
  const bridge = window.__mbfBridge;
  const isAdbAvailable = bridge?.isAdbAvailable ?? false;
  const isBridgeAvailable = bridge?.isAvailable === true;

  const { entries: logEntries, log, clear: clearLog } = useLog();

  const [connections, setConnections] = useState<Map<string, ConnEntry>>(
    new Map(),
  );

  const [versionResult, setVersionResult] = useState("–");
  const [multiResult, setMultiResult] = useState("–");
  const [backpressureStats, setBackpressureStats] = useState({
    chunks: 0,
    bytes: 0,
    max: 0,
    inFlight: 0,
  });

  const [versionRunning, setVersionRunning] = useState(false);
  const [multiRunning, setMultiRunning] = useState(false);
  const [bpRunning, setBpRunning] = useState(false);

  // ── Log init ────────────────────────────────────────────────────────────
  useEffect(() => {
    if (!isBridgeAvailable) {
      log(
        "err",
        "Bridge not available. Load this page via the --test flag inside the Tauri app.",
      );
    } else {
      log(
        "info",
        `isAdbAvailable = ${isAdbAvailable}`,
      );
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Connection helpers ──────────────────────────────────────────────────
  const openConnection = useCallback(async () => {
    if (!bridge) return;
    log("info", "Connecting…");
    try {
      const conn = await bridge.connect();
      log("info", `Connected: ${conn.id}`);
      setConnections((prev) => new Map(prev).set(conn.id, { conn, open: true }));

      conn.onData((data) => {
        log("rx", `← [${conn.id.slice(0, 8)}…] ${hexDump(data)}`);
      });
      conn.onClose(() => {
        log("info", `Closed: ${conn.id.slice(0, 8)}…`);
        setConnections((prev) => {
          const next = new Map(prev);
          const entry = next.get(conn.id);
          if (entry) next.set(conn.id, { ...entry, open: false });
          return next;
        });
      });
    } catch (e) {
      log("err", `connect() failed: ${(e as Error).message}`);
    }
  }, [bridge, log]);

  const closeAll = useCallback(() => {
    setConnections((prev) => {
      prev.forEach(({ conn }) => conn.close());
      return prev;
    });
  }, []);

  // ── ADB version test ────────────────────────────────────────────────────
  const runVersionTest = useCallback(async () => {
    if (!bridge) return;
    setVersionRunning(true);
    setVersionResult("Running…");
    log("info", "--- ADB Version Test ---");
    try {
      const conn = await bridge.connect();
      log("info", `Connection opened: ${conn.id.slice(0, 8)}…`);
      const payload = await adbRequest(conn, "host:version", log);
      const version = parseInt(dec.decode(payload), 16);
      const msg = `ADB server version: ${version} (0x${version.toString(16)})`;
      setVersionResult(`✅ ${msg}`);
      log("info", msg);
      await conn.close();
      log("info", "Connection closed cleanly.");
    } catch (e) {
      const msg = (e as Error).message;
      setVersionResult(`❌ ${msg}`);
      log("err", `Version test failed: ${msg}`);
    }
    setVersionRunning(false);
  }, [bridge, log]);

  // ── Multi-connection test ───────────────────────────────────────────────
  const runMultiTest = useCallback(async () => {
    if (!bridge) return;
    setMultiRunning(true);
    setMultiResult("Running…");
    const N = 3;
    log("info", `--- Multi-Connection Test (${N} simultaneous) ---`);
    try {
      const results = await Promise.all(
        Array.from({ length: N }, async (_, i) => {
          const conn = await bridge.connect();
          log("info", `[${i}] Opened ${conn.id.slice(0, 8)}…`);
          const payload = await adbRequest(conn, "host:version", log);
          const version = parseInt(dec.decode(payload), 16);
          log("info", `[${i}] version=${version}`);
          await conn.close();
          return version;
        }),
      );
      const allSame = results.every((v) => v === results[0]);
      setMultiResult(
        `✅ All ${N} connections reported version ${results[0]}${allSame ? "" : ` – WARNING: mismatch! ${JSON.stringify(results)}`}`,
      );
      log("info", "All connections closed cleanly.");
    } catch (e) {
      const msg = (e as Error).message;
      setMultiResult(`❌ ${msg}`);
      log("err", `Multi-connection test failed: ${msg}`);
    }
    setMultiRunning(false);
  }, [bridge, log]);

  // ── Back-pressure test ──────────────────────────────────────────────────
  const runBpTest = useCallback(async () => {
    if (!bridge) return;
    setBpRunning(true);
    let chunkCount = 0;
    let byteCount = 0;
    let inFlight = 0;
    let maxInFlight = 0;

    setBackpressureStats({ chunks: 0, bytes: 0, max: 0, inFlight: 0 });
    log("info", "--- Back-Pressure Test ---");
    log(
      "info",
      "onData callback will sleep 150 ms per chunk to stress flow control.",
    );

    try {
      const conn = await bridge.connect();
      log("info", `Opened ${conn.id.slice(0, 8)}…`);

      const unlisten = conn.onData(async (data) => {
        inFlight++;
        if (inFlight > maxInFlight) maxInFlight = inFlight;
        chunkCount++;
        byteCount += data.length;
        setBackpressureStats({
          chunks: chunkCount,
          bytes: byteCount,
          max: maxInFlight,
          inFlight,
        });
        log(
          "rx",
          `chunk #${chunkCount} (${data.length} B) – sleeping 150 ms`,
        );
        await new Promise<void>((r) => setTimeout(r, 150));
        inFlight--;
        setBackpressureStats((s) => ({ ...s, inFlight }));
      });

      conn.onClose(() => {
        log("info", "Connection closed after back-pressure test.");
        unlisten();
      });

      const payload = await adbRequest(conn, "host:devices-l", log);
      log("rx", `devices-l: ${dec.decode(payload).trim()}`);

      await conn.close();
      log(
        "info",
        `Back-pressure test complete. Max in-flight permits used: ${maxInFlight}`,
      );
      if (maxInFlight <= WINDOW_SIZE) {
        log(
          "info",
          `✅ Flow control respected (max ${maxInFlight} ≤ ${WINDOW_SIZE})`,
        );
      } else {
        log(
          "warn",
          `⚠️  Flow control exceeded window (${maxInFlight} > ${WINDOW_SIZE})`,
        );
      }
    } catch (e) {
      log("err", `Back-pressure test failed: ${(e as Error).message}`);
    }
    setBpRunning(false);
  }, [bridge, log]);

  // ── Derived state ───────────────────────────────────────────────────────
  const connArray = Array.from(connections.entries());
  const hasOpenConns = connArray.some(([, e]) => e.open);

  // ── Banner ──────────────────────────────────────────────────────────────
  let bannerCls = "warn";
  let bannerMsg = "⚠️  isAdbAvailable is false – check adbd is running.";
  if (!isBridgeAvailable) {
    bannerCls = "err";
    bannerMsg =
      "❌  window.__mbfBridge is not defined – load this page via --test inside the Tauri app.";
  } else if (isAdbAvailable) {
    bannerCls = "ok";
    bannerMsg = "✅  Bridge available – ADB commands enabled.";
  }

  return (
    <div className={styles.page}>
      <div>
        <h1 className={styles.pageTitle}>MBF Bridge – Test Page</h1>
        <h2 className={styles.pageSubtitle}>Tauri 2 ADB IPC bridge validation</h2>
      </div>

      <div className={`${shared.banner} ${shared[bannerCls]}`}>{bannerMsg}</div>

      {/* ── Two-column grid ───────────────────────────────────────────── */}
      <div className={styles.grid}>
        {/* Live device scanner */}
        <DevicesCard enabled={isAdbAvailable} />

        {/* Connections */}
        <div className={shared.card}>
          <div className={shared.cardHeader}>
            <span className={shared.cardTitle}>Connections</span>
          </div>
          <div className={shared.cardBody}>
            <div className={shared.btnRow}>
              <button
                className={shared.btn}
                disabled={!isBridgeAvailable}
                onClick={openConnection}
              >
                New connection
              </button>
              <button
                className={`${shared.btn} ${shared.danger}`}
                disabled={!hasOpenConns}
                onClick={closeAll}
              >
                Close all
              </button>
            </div>
            <div className={styles.connList}>
              {connArray.map(([id, entry]) => (
                <div key={id} className={styles.connRow}>
                  <div
                    className={styles.connDot}
                    data-open={String(entry.open)}
                  />
                  <span className={styles.connId} title={id}>
                    {id.slice(0, 8)}…
                  </span>
                  <button
                    className={`${shared.btn} ${shared.danger} ${styles.closeBtn}`}
                    disabled={!entry.open}
                    onClick={() => entry.conn.close()}
                  >
                    Close
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ADB version test */}
        <div className={shared.card}>
          <div className={shared.cardHeader}>
            <span className={shared.cardTitle}>ADB Version Test</span>
          </div>
          <div className={shared.cardBody}>
            <p className={styles.cardDesc}>
              Sends <code>host:version</code> to the ADB server and parses the
              reply.
            </p>
            <div className={shared.btnRow}>
              <button
                className={shared.btn}
                disabled={!isAdbAvailable || versionRunning}
                onClick={runVersionTest}
              >
                Run test
              </button>
            </div>
            <div className={styles.testResult}>{versionResult}</div>
          </div>
        </div>

        {/* Multi-connection test */}
        <div className={shared.card}>
          <div className={shared.cardHeader}>
            <span className={shared.cardTitle}>Multi-Connection Test</span>
          </div>
          <div className={shared.cardBody}>
            <p className={styles.cardDesc}>
              Opens 3 connections simultaneously, runs the version test on each,
              verifies all succeed independently.
            </p>
            <div className={shared.btnRow}>
              <button
                className={shared.btn}
                disabled={!isAdbAvailable || multiRunning}
                onClick={runMultiTest}
              >
                Run (3 connections)
              </button>
            </div>
            <div className={styles.testResult2}>{multiResult}</div>
          </div>
        </div>

        {/* Back-pressure test */}
        <div className={shared.card}>
          <div className={shared.cardHeader}>
            <span className={shared.cardTitle}>Back-Pressure Test</span>
          </div>
          <div className={shared.cardBody}>
            <p className={styles.cardDesc}>
              Streams ADB <code>host:devices-l</code> with an artificial 150 ms
              delay per chunk. The meter shows in-flight permits (should stay ≤
              8).
            </p>
            <div className={shared.btnRow}>
              <button
                className={shared.btn}
                disabled={!isAdbAvailable || bpRunning}
                onClick={runBpTest}
              >
                Run test
              </button>
            </div>
            <FlowMeter inFlight={backpressureStats.inFlight} />
            <div className={styles.statsRow}>
              {(
                [
                  ["Chunks", backpressureStats.chunks],
                  ["Bytes", backpressureStats.bytes],
                  ["Max in-flight", backpressureStats.max],
                ] as const
              ).map(([label, val]) => (
                <div key={label} className={styles.statBlock}>
                  <div className={styles.statValue}>{val}</div>
                  <div className={styles.statLabel}>{label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Event log */}
      <div className={`${shared.card} ${styles.logCard}`}>
        <div className={shared.cardHeader}>
          <span className={shared.cardTitle}>Event Log</span>
        </div>
        <div className={shared.cardBody}>
          <div className={`${shared.btnRow} ${styles.logBtnRow}`}>
            <button className={`${shared.btn} ${shared.secondary}`} onClick={clearLog}>
              Clear
            </button>
          </div>
          <LogPane entries={logEntries} />
        </div>
      </div>
    </div>
  );
}
