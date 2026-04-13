import { useState, useEffect } from "react";
import shared from "../styles/shared.module.css";
import styles from "./HelpCard.module.css";

export type CliOption = {
  short?: string;
  long?: string;
  valueName?: string;
  description: string;
  defaultValue?: string;
};

export type CliSection = {
  name: string;
  options: CliOption[];
};

export type CliHelp = {
  title?: string;
  usage?: string;
  sections: CliSection[];
};

export function parseHelp(text: string): CliHelp {
  const lines = text.split(/\r?\n/);

  const result: CliHelp = {
    sections: [],
  };

  let currentSection: CliSection | null = null;

  const sectionHeaderRegex = /^([A-Za-z ].+):$/;
  const optionRegex =
    /^\s*(?:(-\w),\s*)?(--[\w-]+)?(?:\s+<([^>]+)>)?\s{2,}(.+)$/;
  const defaultRegex = /\[default:\s*([^\]]+)\]/;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (!line.trim()) continue;

    // ===== Title (first non-empty line) =====
    if (!result.title) {
      result.title = line.trim();
      continue;
    }

    // ===== Usage =====
    if (line.startsWith("Usage:")) {
      result.usage = line.trim();
      continue;
    }

    // ===== Section header =====
    const sectionMatch = line.match(sectionHeaderRegex);
    if (sectionMatch) {
      currentSection = {
        name: sectionMatch[1].trim(),
        options: [],
      };
      result.sections.push(currentSection);
      continue;
    }

    // ===== Option line =====
    const optMatch = line.match(optionRegex);
    if (optMatch && currentSection) {
      const [, short, long, valueName, descRaw] = optMatch;

      let description = descRaw.trim();
      let defaultValue: string | undefined;

      const defaultMatch = description.match(defaultRegex);
      if (defaultMatch) {
        defaultValue = defaultMatch[1];
        description = description.replace(defaultRegex, "").trim();
      }

      currentSection.options.push({
        short: short || undefined,
        long: long || undefined,
        valueName: valueName || undefined,
        description,
        defaultValue,
      });

      continue;
    }
  }

  return result;
}

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
