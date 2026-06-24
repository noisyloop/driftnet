import { useEffect, useRef } from "react";
import type { LogEntry } from "../types";

interface Props {
  log: LogEntry[];
  scanning: boolean;
}

const pad = (n: number) => n.toString().padStart(2, "0");

function clock(ts: number): string {
  const d = new Date(Math.floor(ts));
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function ScanLog({ log, scanning }: Props) {
  const bodyRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to the newest line.
  useEffect(() => {
    const el = bodyRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [log]);

  return (
    <div className="panel scanlog">
      <div className="panel-head">
        <span className="panel-title">scan log</span>
        <span className="panel-meta">
          {scanning ? (
            <span className="live">● live</span>
          ) : (
            <span className="dim">idle</span>
          )}
        </span>
      </div>
      <div className="panel-body log-body" ref={bodyRef}>
        {log.length === 0 ? (
          <div className="empty">log empty — awaiting scan</div>
        ) : (
          log.map((e, i) => (
            <div key={i} className={`log-line log-${e.level}`}>
              <span className="log-ts">{clock(e.ts)}</span>
              <span className="log-tag">{e.level.toUpperCase()}</span>
              <span className="log-msg">{e.msg}</span>
            </div>
          ))
        )}
        {scanning && <div className="log-line log-info cursor">▌</div>}
      </div>
    </div>
  );
}
