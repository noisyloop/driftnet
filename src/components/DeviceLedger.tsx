import { useMemo, useState } from "react";
import type { DeviceRecord } from "../types";
import { riskClass, stamp, timeAgo } from "../lib/format";

type SortKey = "risk" | "firstSeen" | "lastSeen" | "ip";

interface Props {
  devices: DeviceRecord[];
  selectedIp: string | null;
  onSelect: (ip: string) => void;
}

const HEADERS: { key: SortKey; label: string }[] = [
  { key: "ip", label: "host" },
  { key: "risk", label: "risk" },
  { key: "firstSeen", label: "first seen" },
  { key: "lastSeen", label: "last seen" },
];

export function DeviceLedger({ devices, selectedIp, onSelect }: Props) {
  const [sortKey, setSortKey] = useState<SortKey>("risk");
  const [asc, setAsc] = useState(false);

  const sorted = useMemo(() => {
    const arr = [...devices];
    arr.sort((a, b) => {
      let cmp = 0;
      switch (sortKey) {
        case "risk":
          cmp = a.riskScore - b.riskScore;
          break;
        case "firstSeen":
          cmp = a.firstSeen - b.firstSeen;
          break;
        case "lastSeen":
          cmp = a.lastSeen - b.lastSeen;
          break;
        case "ip":
          cmp = a.ip.localeCompare(b.ip, undefined, { numeric: true });
          break;
      }
      return asc ? cmp : -cmp;
    });
    return arr;
  }, [devices, sortKey, asc]);

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) setAsc((v) => !v);
    else {
      setSortKey(key);
      setAsc(false);
    }
  };

  return (
    <div className="panel ledger">
      <div className="panel-head">
        <span className="panel-title">device ledger</span>
        <span className="panel-meta">{devices.length} known</span>
      </div>
      <div className="panel-body">
        {sorted.length === 0 ? (
          <div className="empty">no devices recorded — run a scan</div>
        ) : (
          <table className="ledger-table">
            <thead>
              <tr>
                {HEADERS.map((h) => (
                  <th
                    key={h.key}
                    onClick={() => toggleSort(h.key)}
                    className={sortKey === h.key ? "sorted" : ""}
                  >
                    {h.label}
                    {sortKey === h.key ? (asc ? " ▲" : " ▼") : ""}
                  </th>
                ))}
                <th>ports</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((d) => (
                <tr
                  key={d.ip}
                  className={d.ip === selectedIp ? "selected" : ""}
                  onClick={() => onSelect(d.ip)}
                >
                  <td className="mono">
                    <span className={`fam-badge fam-${d.ipVersion}`}>
                      v{d.ipVersion}
                    </span>{" "}
                    {d.ip}
                    <span className="ipclass">{d.ipClass}</span>
                  </td>
                  <td>
                    <span className={`risk-badge ${riskClass(d.riskLevel)}`}>
                      {d.riskLevel}
                    </span>
                    <span className="risk-num">{d.riskScore}</span>
                  </td>
                  <td title={stamp(d.firstSeen)}>{timeAgo(d.firstSeen)}</td>
                  <td title={stamp(d.lastSeen)}>{timeAgo(d.lastSeen)}</td>
                  <td className="mono dim">{d.portSignature}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
