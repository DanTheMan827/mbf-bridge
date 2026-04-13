import { useState, useEffect } from "react";
import shared from "../styles/shared.module.css";
import styles from "./HelpCard.module.css";

function getInvoke() {
  return window.__TAURI__?.core.invoke ?? null;
}

export default function HelpCard() {
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
    <div className={`${shared.card} ${styles.helpFill}`}>
      <div className={shared.cardHeader}>
        <span className={shared.cardTitle}>Available Arguments</span>
      </div>
      <div className={shared.cardBody}>
        <div className={styles.helpScroll}>
          <pre className={styles.helpPre}>{helpText}</pre>
        </div>
      </div>
    </div>
  );
}
