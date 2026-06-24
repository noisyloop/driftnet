import { useCallback, useRef, useState } from "react";
import type { LogEntry, Observation } from "../types";
import { classifyIp } from "../lib/ipClass";
import { observerFingerprint } from "../lib/fingerprint";
import { enumerateCandidates, STUN_URL } from "../lib/webrtc";
import {
  COMMON_PORTS,
  estimateRtt,
  portSignature,
  probeHost,
} from "../lib/portProbe";

export interface ScannerApi {
  scanning: boolean;
  log: LogEntry[];
  /** Run a full discovery + probe sweep, emitting each observation. */
  scan: (onObservation: (obs: Observation) => void) => Promise<void>;
  clearLog: () => void;
}

let logSeq = 0;

/**
 * useNetworkScanner — orchestrates discovery (WebRTC ICE) and per-host port
 * probing, streaming a live log. It does not persist anything; observations are
 * handed to the caller (typically wired into useDeviceLedger.record).
 */
export function useNetworkScanner(): ScannerApi {
  const [scanning, setScanning] = useState(false);
  const [log, setLog] = useState<LogEntry[]>([]);
  const runningRef = useRef(false);

  const emit = useCallback((level: LogEntry["level"], msg: string) => {
    // logSeq guarantees stable ordering even within the same millisecond.
    const entry: LogEntry = { ts: Date.now() + logSeq++ * 1e-6, level, msg };
    setLog((prev) => [...prev, entry].slice(-200));
  }, []);

  const clearLog = useCallback(() => setLog([]), []);

  const scan = useCallback(
    async (onObservation: (obs: Observation) => void) => {
      if (runningRef.current) return;
      runningRef.current = true;
      setScanning(true);

      const fingerprint = observerFingerprint();
      emit("info", `observer fingerprint :: ${fingerprint}`);
      emit("info", `gathering ICE candidates via ${STUN_URL} …`);

      try {
        const { ips, raw } = await enumerateCandidates((candidate, ip) => {
          emit("info", `candidate ${ip ?? "(mDNS/obfuscated)"} ← ${candidate.split(" ").slice(0, 5).join(" ")}`);
        });

        if (!raw.length) {
          emit("warn", "no ICE candidates returned (WebRTC blocked?).");
        }

        const targets = ips.filter((ip) => classifyIp(ip) !== "unknown");
        if (!targets.length) {
          emit("warn", "no resolvable IPv4 hosts discovered.");
          return;
        }
        emit("ok", `discovered ${targets.length} host(s): ${targets.join(", ")}`);

        for (const ip of targets) {
          const cls = classifyIp(ip);
          emit(
            cls === "public" ? "crit" : cls === "link-local" ? "warn" : "info",
            `probing ${ip} [${cls}] ports ${COMMON_PORTS.join("/")} …`,
          );

          const portProfile = await probeHost(ip);
          const sig = portSignature(portProfile);
          const rtt = estimateRtt(portProfile);
          const openPorts = portProfile.filter((p) => p.open).map((p) => p.port);

          emit(
            openPorts.length ? "ok" : "info",
            `${ip} → open:[${openPorts.join(",") || "none"}] rtt~${rtt}ms`,
          );

          const obs: Observation = {
            ip,
            ipClass: cls,
            rttMs: rtt,
            portProfile,
            portSignature: sig,
            fingerprintHash: fingerprint,
          };
          onObservation(obs);
        }

        emit("ok", "sweep complete.");
      } catch (err) {
        emit("warn", `scan error :: ${(err as Error).message ?? String(err)}`);
      } finally {
        runningRef.current = false;
        setScanning(false);
      }
    },
    [emit],
  );

  return { scanning, log, scan, clearLog };
}
