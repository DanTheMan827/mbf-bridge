import { useCallback, useEffect, useState } from "preact/hooks";
import shared from "../styles/shared.module.css";
import styles from "./ShiftPage.module.css";
import HelpCard from "../components/HelpCard";

const STORAGE_KEY = "mbf-bridge-launch-args";

function getInvoke() {
  return window.__TAURI__?.core.invoke ?? null;
}

export default function ShiftPage() {
  const modifierKey = window.__mbfModifierKey ?? "Shift";
  const invoke = getInvoke();

  const [args, setArgs] = useState<string>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) ?? "";
    } catch {
      return "";
    }
  });
  const [status, setStatus] = useState<{ msg: string; cls: string }>({
    msg: "",
    cls: "",
  });
  const [launching, setLaunching] = useState(false);

  // Persist args on every change.
  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, args);
    } catch {
      // ignore
    }
  }, [args]);

  const doLaunch = useCallback(async () => {
    if (!invoke || launching) return;
    setLaunching(true);
    setStatus({ msg: "Launching\u2026", cls: "" });
    try {
      await invoke("launch_with_args", { args });
      // The window will be closed by Rust after spawning the new instance.
    } catch (e: unknown) {
      setStatus({ msg: `Error: ${e}`, cls: "err" });
      setLaunching(false);
    }
  }, [invoke, launching, args]);

  // Ctrl+Enter / Cmd+Enter keyboard shortcut.
  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        doLaunch();
      }
    },
    [doLaunch],
  );

  return (
    <div className={styles.page}>
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <header className={styles.header}>
        <div aria-hidden className={styles.logoIcon}>
          {/* Play icon */}
          <svg
            viewBox="0 0 24 24"
            width="1.25rem"
            height="1.25rem"
            fill="white"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path d="M8 5v14l11-7z" />
          </svg>
        </div>
        <div>
          <h1 className={styles.pageTitle}>ModsBeforeFriday Bridge</h1>
          <p className={styles.pageSubtitle}>
            Hold <kbd>{modifierKey}</kbd> at startup to open this window.
          </p>
        </div>
      </header>

      {/* ── Help text ───────────────────────────────────────────────────── */}
      <HelpCard />

      {/* ── Custom args + launch ─────────────────────────────────────────── */}
      <div className={shared.card}>
        <div className={shared.cardHeader}>
          <span className={shared.cardTitle}>Custom Arguments</span>
        </div>
        <div className={shared.cardBody}>
          <div className={styles.argsRow}>
            <textarea
              value={args}
              onChange={(e) => setArgs((e.target as HTMLTextAreaElement).value)}
              onKeyDown={handleKeyDown}
              rows={2}
              placeholder="e.g. --url https://example.com --dev --adb-port 5038"
              spellcheck={false}
              autoCorrect="off"
              autoCapitalize="off"
              className={styles.textarea}
            />
            <button
              className={`${shared.btn} ${styles.launchBtn}`}
              disabled={!invoke || launching}
              onClick={doLaunch}
            >
              <svg
                viewBox="0 0 24 24"
                width="0.9rem"
                height="0.9rem"
                fill="currentColor"
                xmlns="http://www.w3.org/2000/svg"
                aria-hidden
              >
                <path d="M8 5v14l11-7z" />
              </svg>
              Launch
            </button>
          </div>

          {/* Status line */}
          {status.msg && (
            <div data-cls={status.cls} className={styles.statusLine}>
              {status.msg}
            </div>
          )}
        </div>
      </div>

      {/* ── Footer hint ──────────────────────────────────────────────────── */}
      <p className={styles.footer}>
        Arguments are saved automatically. Press <kbd>Ctrl+Enter</kbd> to
        launch.
      </p>
    </div>
  );
}
