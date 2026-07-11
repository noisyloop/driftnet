import { useCallback, useMemo, useState } from "react";
import { useDeviceLedger } from "./hooks/useDeviceLedger";
import { useNetworkScanner } from "./hooks/useNetworkScanner";
import { useEgressConfig } from "./hooks/useEgressConfig";
import { DeviceLedger } from "./components/DeviceLedger";
import { DetailPane } from "./components/DetailPane";
import { ScanLog } from "./components/ScanLog";
import { EgressPanel } from "./components/EgressPanel";
import { observerFingerprint } from "./lib/fingerprint";

export default function App() {
  const ledger = useDeviceLedger();
  const scanner = useNetworkScanner();
  const { egress, setEgress } = useEgressConfig();
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [egressOpen, setEgressOpen] = useState(false);

  const selected = useMemo(
    () => ledger.devices.find((d) => d.ip === selectedIp) ?? null,
    [ledger.devices, selectedIp],
  );

  const handleScan = useCallback(() => {
    scanner.scan((obs, sweep) => {
      const rec = ledger.record(obs, egress, sweep);
      // Auto-select the first thing we find if nothing is selected.
      setSelectedIp((cur) => cur ?? rec.ip);
    });
  }, [scanner, ledger, egress]);

  const handleClear = useCallback(() => {
    if (
      window.confirm(
        "Clear the entire device ledger? This wipes driftnet:devices from localStorage.",
      )
    ) {
      ledger.clear();
      setSelectedIp(null);
    }
  }, [ledger]);

  const fp = observerFingerprint();
  const criticalCount = ledger.devices.filter(
    (d) => d.riskLevel === "CRITICAL",
  ).length;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark">▚</span>
          <span className="brand-name">driftnet</span>
          <span className="brand-sub">rogue device correlation engine</span>
        </div>
        <div className="topbar-meta">
          <span className="obs" title="observer fingerprint">
            obs::{fp}
          </span>
          {(egress?.expectedIpv4 || egress?.expectedIpv6) && (
            <span className="obs mono" title="expected egress baseline">
              egress::{egress.expectedIpv4 ?? egress.expectedIpv6}
              {egress.label ? ` (${egress.label})` : ""}
            </span>
          )}
          {criticalCount > 0 && (
            <span className="crit-flag">{criticalCount} CRITICAL</span>
          )}
        </div>
        <div className="controls">
          <button
            className="btn btn-primary"
            onClick={handleScan}
            disabled={scanner.scanning}
          >
            {scanner.scanning ? "scanning…" : "rescan"}
          </button>
          <button
            className={`btn${egressOpen ? " btn-primary" : ""}`}
            onClick={() => setEgressOpen((v) => !v)}
          >
            egress
          </button>
          <button
            className="btn"
            onClick={scanner.clearLog}
            disabled={scanner.scanning}
          >
            clear log
          </button>
          <button
            className="btn btn-danger"
            onClick={handleClear}
            disabled={scanner.scanning}
          >
            clear ledger
          </button>
        </div>
      </header>

      {egressOpen && (
        <EgressPanel
          egress={egress}
          onChange={setEgress}
          onClose={() => setEgressOpen(false)}
        />
      )}

      <main className="grid">
        <DeviceLedger
          devices={ledger.devices}
          selectedIp={selectedIp}
          onSelect={setSelectedIp}
        />
        <DetailPane device={selected} egress={egress} />
        <ScanLog log={scanner.log} scanning={scanner.scanning} />
      </main>

      <footer className="statusbar">
        <span>
          passive local-network intelligence · browser APIs only · no packets ·
          no server
        </span>
        <span className="dim">stun.l.google.com:19302</span>
      </footer>
    </div>
  );
}
