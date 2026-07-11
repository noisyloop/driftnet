import { useCallback, useRef, useState } from "react";
import type { LogEntry, Observation, SweepFace } from "../types";
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
  scan: (
    onObservation: (obs: Observation, sweep: SweepFace[]) => void,
  ) => Promise<void>;
  clearLog: () => void;
}

let logSeq = 0;

/**
 * useNetworkScanner — orchestrates discovery (WebRTC ICE) and per-host port
 * probing, streaming a live log. It does not persist anything; observations
 * (plus the full sweep of discovered faces, for cross-family correlation) are
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
    async (onObservation: (obs: Observation, sweep: SweepFace[]) => void) => {
      if (runningRef.current) return;
      runningRef.current = true;
      setScanning(true);

      const fingerprint = observerFingerprint();
      emit("info", `observer fingerprint :: ${fingerprint}`);
      emit("info", `gathering ICE candidates via ${STUN_URL} …`);

      try {
        const { addresses, raw } = await enumerateCandidates(
          (candidate, addr) => {
            const tag = addr
              ? addr.family
                ? `${addr.address} [v${addr.family}]`
                : `${addr.address} [mDNS]`
              : "(unparsed)";
            emit(
              "info",
              `candidate ${tag} ← ${candidate.split(" ").slice(0, 5).join(" ")}`,
            );
          },
        );

        if (!raw.length) {
          emit("warn", "no ICE candidates returned (WebRTC blocked?).");
        }

        // mDNS hostnames hide the raw address — surface them, don't probe.
        for (const a of addresses.filter((a) => a.family === null)) {
          emit("warn", `mDNS candidate ${a.address} — obscured, not probed.`);
        }

        const faces: SweepFace[] = addresses.flatMap((a) => {
          if (a.family === null) return [];
          const cls = classifyIp(a.address);
          if (cls === "unknown" || cls === "obscured") return [];
          return [{ ip: a.address, ipClass: cls, ipVersion: a.family }];
        });

        if (!faces.length) {
          emit("warn", "no resolvable hosts discovered.");
          return;
        }
        emit(
          "ok",
          `discovered ${faces.length} face(s): ${faces
            .map((f) => `${f.ip} (v${f.ipVersion})`)
            .join(", ")}`,
        );

        for (const face of faces) {
          const { ip, ipClass: cls, ipVersion } = face;
          emit(
            cls === "public" ? "crit" : cls === "link-local" ? "warn" : "info",
            `probing ${ip} [v${ipVersion} ${cls}] ports ${COMMON_PORTS.join("/")} …`,
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
            ipVersion,
            rttMs: rtt,
            portProfile,
            portSignature: sig,
            fingerprintHash: fingerprint,
          };
          onObservation(obs, faces);
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
