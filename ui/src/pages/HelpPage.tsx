import styles from "./HelpPage.module.css";
import HelpCard from "../components/HelpCard";



export default function HelpPage() {
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
      <HelpCard />

      {/* ── Footer hint ──────────────────────────────────────────────────── */}
      <p className={styles.footer}>
        Pass these arguments when launching from a terminal.
      </p>
    </div>
  );
}
