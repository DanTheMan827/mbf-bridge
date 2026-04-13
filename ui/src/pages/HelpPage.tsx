import { useEffect, useState } from "react";
import shared from "../styles/shared.module.css";
import styles from "./HelpPage.module.css";

function getInvoke() {
  return window.__TAURI__?.core.invoke ?? null;
}

export default function HelpPage() {
  const invoke = getInvoke();
  const [helpText, setHelpText] = useState<string>("Loading…");

  // Load help text via Tauri IPC.
  useEffect(() => {
    if (!invoke) {
      setHelpText("(Tauri IPC not available)");
      return;
    }
    invoke<string>("get_help_text")
      .then((t) => setHelpText(t))
      .catch((e: unknown) => setHelpText(`(failed to load help: ${e})`));
  }, [invoke]);

  return (
    <div className={styles.page}>
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <header className={styles.header}>
        <div aria-hidden className={styles.logoIcon}>
          {/* Info icon */}
          <svg
            viewBox="0 0 24 24"
            width="1.25rem"
            height="1.25rem"
            fill="white"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-6h2v6zm0-8h-2V7h2v2z" />
          </svg>
        </div>
        <div>
          <h1 className={styles.pageTitle}>ModsBeforeFriday Bridge – Help</h1>
          <p className={styles.pageSubtitle}>
            Available command-line arguments
          </p>
        </div>
      </header>

      {/* ── Help text ───────────────────────────────────────────────────── */}
      <div className={shared.card}>
        <div className={shared.cardHeader}>
          <span className={shared.cardTitle}>Available Arguments</span>
        </div>
        <div className={shared.cardBody}>
          <div className={styles.helpScroll}>
            <pre className={styles.helpPre}>{helpText}</pre>
          </div>
        </div>
      </div>

      {/* ── Footer hint ──────────────────────────────────────────────────── */}
      <p className={styles.footer}>
        Pass these arguments when launching from a terminal or a jump list
        entry.
      </p>
    </div>
  );
}
