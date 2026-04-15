import { useEffect, useRef, useState } from "preact/hooks";
import styles from "./WingetProgressPage.module.css";

interface WingetOutputPayload { data: number[] }
interface WingetDonePayload   { success: boolean }

// ---------------------------------------------------------------------------
// Minimal ANSI → HTML renderer  (~2 KB, replaces xterm.js ~400 KB)
// ---------------------------------------------------------------------------

/** Convert a list of SGR parameter codes into an inline CSS snippet. */
function sgrToCss(params: number[]): string {
  const NORMAL = ["#111","#c33","#3a3","#880","#33c","#c3c","#3cc","#ccc"];
  const BRIGHT = ["#555","#f55","#5f5","#ff5","#55f","#f5f","#5ff","#fff"];
  let css = "";
  for (const p of params) {
    if      (p === 0)             css = "";
    else if (p === 1)             css += "font-weight:bold;";
    else if (p === 22)            css += "font-weight:normal;";
    else if (p >= 30 && p <= 37)  css += `color:${NORMAL[p - 30]};`;
    else if (p >= 90 && p <= 97)  css += `color:${BRIGHT[p - 90]};`;
    else if (p === 39)            css = css.replace(/color:[^;]+;/g, "");
  }
  return css;
}

/** Mutable virtual terminal that tracks lines and SGR state. */
class AnsiScreen {
  private lines: Array<Array<{ t: string; s: string }>> = [[]];
  private row = 0;
  private col = 0;
  private css = "";

  write(data: Uint8Array): void {
    const text = new TextDecoder().decode(data);
    let i = 0;
    while (i < text.length) {
      const ch = text[i];

      if (ch === "\r") {
        this.lines[this.row] ??= [];
        this.col = 0;
        i++;
      } else if (ch === "\n") {
        this.row++;
        while (this.row >= this.lines.length) this.lines.push([]);
        this.col = 0;
        i++;
      } else if (ch === "\x1b" && text[i + 1] === "[") {
        // CSI sequence: scan to the final byte (0x40–0x7E, i.e. '@' through '~')
        const CSI_FINAL_MIN = 0x40; // '@'
        const CSI_FINAL_MAX = 0x7e; // '~'
        let j = i + 2;
        while (j < text.length && (text.charCodeAt(j) < CSI_FINAL_MIN || text.charCodeAt(j) > CSI_FINAL_MAX)) j++;
        const cmd = text[j] ?? "";
        const params = text.slice(i + 2, j).split(";").map((s) => parseInt(s || "0", 10));
        switch (cmd) {
          case "m": this.css = sgrToCss(params); break;
          case "A": this.row = Math.max(0, this.row - (params[0] || 1)); break;
          case "B":
            this.row += (params[0] || 1);
            while (this.row >= this.lines.length) this.lines.push([]);
            break;
          case "J": if (params[0] === 2) { this.lines = [[]]; this.row = 0; } break;
          case "K": this.lines[this.row] = []; break;
        }
        i = j + 1;
      } else if (ch === "\x1b") {
        i += 2;
      } else {
        // Write character at current row/col, overwriting if needed
        this.lines[this.row] ??= [];
        const line = this.lines[this.row];
        // Find the segment at this.col
        let col = this.col;
        let segIdx = 0;
        let charCount = 0;
        // Find the segment and offset within segment for this.col
        while (segIdx < line.length && charCount + line[segIdx].t.length <= col) {
          charCount += line[segIdx].t.length;
          segIdx++;
        }
        if (col < this.lineLength(line)) {
          // Overwrite existing character
          if (segIdx < line.length) {
            const seg = line[segIdx];
            const offset = col - charCount;
            if (seg.s === this.css) {
              // Overwrite in-place
              seg.t = seg.t.substring(0, offset) + ch + seg.t.substring(offset + 1);
            } else {
              // Split segment if needed
              const before = seg.t.substring(0, offset);
              const after = seg.t.substring(offset + 1);
              const newSegs = [];
              if (before) newSegs.push({ t: before, s: seg.s });
              newSegs.push({ t: ch, s: this.css });
              if (after) newSegs.push({ t: after, s: seg.s });
              // Replace seg with newSegs
              line.splice(segIdx, 1, ...newSegs);
            }
          }
        } else {
          // Append at end
          if (line.length && line[line.length - 1].s === this.css) {
            line[line.length - 1].t += ch;
          } else {
            line.push({ t: ch, s: this.css });
          }
        }
        this.col++;
        i++;
      }
    }
  }

  /** Returns the total number of characters in a line (across all segments). */
  private lineLength(line: Array<{ t: string; s: string }>): number {
    return line.reduce((sum, seg) => sum + seg.t.length, 0);
  }

  toHTML(): string {
    return this.lines
      .map((line) =>
        line.map((seg) => {
          const txt = seg.t
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
          return seg.s ? `<span style="${seg.s}">${txt}</span>` : txt;
        }).join("")
      ).join("\n");
  }
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

function getInvoke() { return window.__TAURI__?.core.invoke ?? null; }
function getListen()  { return window.__TAURI__?.event.listen  ?? null; }

export default function WingetProgressPage() {
  const preRef   = useRef<HTMLPreElement>(null);
  const screen   = useRef(new AnsiScreen());
  const [done,    setDone]    = useState(false);
  const [success, setSuccess] = useState(false);

  useEffect(() => {
    const listen = getListen();
    if (!listen) return;

    const flush = () => {
      if (preRef.current) {
        // Safe: toHTML() escapes &, < and > before inserting into spans.
        // Source data comes exclusively from the local winget process via
        // the Tauri Rust backend — no external actor can inject arbitrary HTML.
        preRef.current.innerHTML = screen.current.toHTML();
        preRef.current.scrollTop = preRef.current.scrollHeight;
      }
    };

    const unlistenOutput = listen<WingetOutputPayload>("winget-output", (ev) => {
      if (__DEV__) {
        console.debug("[winget-output]", new TextDecoder().decode(new Uint8Array(ev.payload.data)), ev.payload.data);
      }
      screen.current.write(new Uint8Array(ev.payload.data));
      flush();
    });

    const unlistenDone = listen<WingetDonePayload>("winget-done", (ev) => {
      const ok  = ev.payload.success;
      const msg = ok
        ? "\r\n\x1b[32mInstallation complete.\u2026\x1b[0m"
        : "\r\n\x1b[31mInstallation failed or ADB could not be started.\x1b[0m";
      screen.current.write(new TextEncoder().encode(msg));
      flush();
      setSuccess(ok);
      setDone(true);
    });

    return () => {
      void unlistenOutput.then((f) => f());
      void unlistenDone.then((f) => f());
    };
  }, []);

  const handleClose = async () => {
    const invoke = getInvoke();
    if (invoke) await invoke("close_winget_progress_window");
  };

  return (
    <div className={styles.page}>
      <header className={styles.header}>
        <div aria-hidden className={styles.logoIcon}>
          <svg viewBox="0 0 24 24" width="1.25rem" height="1.25rem" fill="white" xmlns="http://www.w3.org/2000/svg">
            <path d="M19 9h-4V3H9v6H5l7 7 7-7zm-8 2V5h2v6h1.17L12 13.17 9.83 11H11zm-6 8h14v2H5v-2z" />
          </svg>
        </div>
        <div>
          <h1 className={styles.pageTitle}>Installing Google Platform Tools</h1>
          <p className={styles.pageSubtitle}>
            {done
              ? (success ? "Installation complete." : "Installation failed.")
              : "Please wait while ADB is being installed via winget\u2026"}
          </p>
        </div>
        {!done && <div className={styles.spinner} aria-label="Installing\u2026" />}
      </header>

      <div className={styles.termWrapper}>
        <pre ref={preRef} className={styles.termContainer} />
      </div>

      {done && (
        <div className={styles.footer}>
          {!success && (
            <p className={styles.errorHint}>
              ADB could not be started. Install it manually from{" "}
              <a href="https://developer.android.com/studio/releases/platform-tools" target="_blank" rel="noreferrer">
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
