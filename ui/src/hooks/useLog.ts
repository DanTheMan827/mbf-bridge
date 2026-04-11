import { useCallback, useRef, useState } from "react";

export type LogClass = "tx" | "rx" | "info" | "warn" | "err";

export interface LogEntry {
  id: number;
  ts: string;
  cls: LogClass;
  msg: string;
}

export function useLog() {
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const counterRef = useRef(0);

  const log = useCallback((cls: LogClass, msg: string) => {
    const id = counterRef.current++;
    const ts = new Date().toTimeString().slice(0, 8);
    setEntries((prev) => [...prev, { id, ts, cls, msg }]);
  }, []);

  const clear = useCallback(() => setEntries([]), []);

  return { entries, log, clear };
}
