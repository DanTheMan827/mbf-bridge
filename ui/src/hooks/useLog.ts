import { useCallback, useState } from "preact/hooks";

export type LogClass = "tx" | "rx" | "info" | "warn" | "err";

export interface LogEntry {
  id: number;
  ts: string;
  cls: LogClass;
  msg: string;
}

export function useLog() {
  const [entries, setEntries] = useState<LogEntry[]>([]);

  const log = useCallback((cls: LogClass, msg: string) => {
    const ts = new Date().toTimeString().slice(0, 8);
    setEntries((prev) => {
      const id = prev.length > 0 ? prev[prev.length - 1].id + 1 : 0;
      return [...prev, { id, ts, cls, msg }];
    });
  }, []);

  const clear = useCallback(() => setEntries([]), []);

  return { entries, log, clear };
}
