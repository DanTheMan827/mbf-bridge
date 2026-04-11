import { useCallback, useEffect, useRef, useState } from "react";

const STORAGE_KEY = "mbf-bridge-launch-args";

function getInvoke() {
  return window.__TAURI__?.core.invoke ?? null;
}

export default function ShiftPage() {
  const modifierKey = window.__mbfModifierKey ?? "Shift";
  const invoke = getInvoke();

  const [helpText, setHelpText] = useState<string>("Loading…");
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
  const textareaRef = useRef<HTMLTextAreaElement>(null);

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
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        doLaunch();
      }
    },
    [doLaunch],
  );

  return (
    <div
      style={{
        padding: "1.25rem 1.5rem 1.5rem",
        minHeight: "100%",
        display: "flex",
        flexDirection: "column",
        gap: "1rem",
      }}
    >
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <header style={{ display: "flex", alignItems: "flex-start", gap: "0.75rem" }}>
        <div
          aria-hidden
          style={{
            width: "2.25rem",
            height: "2.25rem",
            borderRadius: 6,
            background: "var(--accent)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
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
          <h1 style={{ fontSize: "1.1rem", fontWeight: 700, lineHeight: 1.25 }}>
            ModsBeforeFriday Bridge
          </h1>
          <p style={{ fontSize: "0.8rem", color: "var(--subtext)", marginTop: "0.2rem" }}>
            Hold <kbd>{modifierKey}</kbd> at startup to open this window.
          </p>
        </div>
      </header>

      {/* ── Help text ───────────────────────────────────────────────────── */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Available Arguments</span>
        </div>
        <div className="card-body">
          <div
            style={{
              maxHeight: 220,
              overflowY: "auto",
              borderRadius: "calc(var(--radius) - 2px)",
            }}
          >
            <pre
              style={{
                fontFamily: "var(--mono)",
                fontSize: "0.775rem",
                lineHeight: 1.65,
                whiteSpace: "pre-wrap",
                wordBreak: "break-word",
              }}
            >
              {helpText}
            </pre>
          </div>
        </div>
      </div>

      {/* ── Custom args + launch ─────────────────────────────────────────── */}
      <div className="card">
        <div className="card-header">
          <span className="card-title">Custom Arguments</span>
        </div>
        <div className="card-body">
          <div style={{ display: "flex", gap: "0.625rem", alignItems: "flex-start" }}>
            <textarea
              ref={textareaRef}
              value={args}
              onChange={(e) => setArgs(e.target.value)}
              onKeyDown={handleKeyDown}
              rows={2}
              placeholder="e.g. --url https://example.com --dev --adb-port 5038"
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="off"
              style={{
                flex: 1,
                background: "var(--bg)",
                border: "1px solid var(--border)",
                borderRadius: "calc(var(--radius) - 2px)",
                color: "var(--text)",
                fontFamily: "var(--mono)",
                fontSize: "0.825rem",
                lineHeight: 1.5,
                padding: "0.5rem 0.75rem",
                resize: "vertical",
                minHeight: "2.4rem",
                outline: "none",
                transition: "border-color 0.15s, box-shadow 0.15s",
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = "var(--accent)";
                e.currentTarget.style.boxShadow =
                  "0 0 0 3px color-mix(in srgb, var(--accent) 20%, transparent)";
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = "var(--border)";
                e.currentTarget.style.boxShadow = "none";
              }}
            />
            <button
              className="btn"
              style={{ flexShrink: 0 }}
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
            <div
              style={{
                marginTop: "0.5rem",
                fontSize: "0.775rem",
                color: status.cls === "err" ? "var(--red)" : "var(--subtext)",
              }}
            >
              {status.msg}
            </div>
          )}
        </div>
      </div>

      {/* ── Footer hint ──────────────────────────────────────────────────── */}
      <p
        style={{
          fontSize: "0.75rem",
          color: "var(--subtext)",
          textAlign: "center",
          marginTop: "auto",
        }}
      >
        Arguments are saved automatically. Press <kbd>Ctrl+Enter</kbd> to
        launch.
      </p>
    </div>
  );
}
