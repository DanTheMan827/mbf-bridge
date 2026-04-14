import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import styles from "./WingetProgressPage.module.css";

interface WingetOutputPayload {
  data: number[];
}

interface WingetDonePayload {
  success: boolean;
}

function getInvoke() {
  return window.__TAURI__?.core.invoke ?? null;
}

function getListen() {
  return window.__TAURI__?.event.listen ?? null;
}

export default function WingetProgressPage() {
  const termRef = useRef<HTMLDivElement>(null);
  const termInstance = useRef<Terminal | null>(null);
  const fitAddon = useRef<FitAddon | null>(null);
  const [done, setDone] = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    const listen = getListen();
    if (!listen || !termRef.current) return;

    // Initialise xterm.js terminal with FitAddon so it fills its container.
    const fit = new FitAddon();
    fitAddon.current = fit;
    const term = new Terminal({
      convertEol: true,
      disableStdin: true,
      scrollback: 5000,
      theme: {
        background: "#0f1117",
        foreground: "#d4d8f0",
        cursor: "#d4d8f0",
        cursorAccent: "#0f1117",
        black: "#0f1117",
        brightBlack: "#6b7280",
        red: "#e05c5c",
        brightRed: "#e05c5c",
        green: "#4caf6e",
        brightGreen: "#4caf6e",
        yellow: "#e0a84d",
        brightYellow: "#e0a84d",
        blue: "#5b8af5",
        brightBlue: "#7ba3ff",
        magenta: "#b07af5",
        brightMagenta: "#c59dff",
        cyan: "#6ec6e0",
        brightCyan: "#8cd8ef",
        white: "#d4d8f0",
        brightWhite: "#ffffff",
      },
    });
    term.loadAddon(fit);
    term.open(termRef.current);
    fit.fit();
    termInstance.current = term;

    // Re-fit whenever the container is resized.
    const ro = new ResizeObserver(() => fit.fit());
    ro.observe(termRef.current);

    // Subscribe to raw output chunks from Rust.
    const unlistenOutput = listen<WingetOutputPayload>(
      "winget-output",
      (event) => {
        term.write(new Uint8Array(event.payload.data));
      }
    );

    // Subscribe to completion signal.
    const unlistenDone = listen<WingetDonePayload>("winget-done", (event) => {
      setSuccess(event.payload.success);
      setDone(true);
      if (event.payload.success) {
        term.writeln(
          "\r\n\x1b[32m✔ Installation complete. Connecting to ADB…\x1b[0m"
        );
      } else {
        term.writeln(
          "\r\n\x1b[31m✖ Installation failed or ADB could not be started.\x1b[0m"
        );
      }
    });

    return () => {
      ro.disconnect();
      void unlistenOutput.then((f) => f());
      void unlistenDone.then((f) => f());
      term.dispose();
      termInstance.current = null;
      fitAddon.current = null;
    };
  }, []);

  const handleClose = async () => {
    const invoke = getInvoke();
    if (invoke) {
      await invoke("close_winget_progress_window");
    }
  };

  return (
    <div className={styles.page}>
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <header className={styles.header}>
        <div aria-hidden className={styles.logoIcon}>
          {/* Download icon */}
          <svg
            viewBox="0 0 24 24"
            width="1.25rem"
            height="1.25rem"
            fill="white"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path d="M19 9h-4V3H9v6H5l7 7 7-7zm-8 2V5h2v6h1.17L12 13.17 9.83 11H11zm-6 8h14v2H5v-2z" />
          </svg>
        </div>
        <div>
          <h1 className={styles.pageTitle}>Installing Google Platform Tools</h1>
          <p className={styles.pageSubtitle}>
            {done
              ? success
                ? "Installation complete."
                : "Installation failed."
              : "Please wait while ADB is being installed via winget…"}
          </p>
        </div>
        {!done && (
          <div className={styles.spinner} aria-label="Installing…" />
        )}
      </header>

      {/* ── Terminal output ──────────────────────────────────────────────── */}
      <div className={styles.termWrapper}>
        <div ref={termRef} className={styles.termContainer} />
      </div>

      {/* ── Footer / action ──────────────────────────────────────────────── */}
      {done && (
        <div className={styles.footer}>
          {!success && (
            <p className={styles.errorHint}>
              ADB could not be started. You can install it manually from{" "}
              <a
                href="https://developer.android.com/studio/releases/platform-tools"
                target="_blank"
                rel="noreferrer"
              >
                developer.android.com
              </a>
              , then restart the app.
            </p>
          )}
          <button className={styles.closeBtn} onClick={handleClose}>
            Close
          </button>
        </div>
      )}
    </div>
  );
}
