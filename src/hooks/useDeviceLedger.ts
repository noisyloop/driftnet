import { useCallback, useEffect, useRef, useState } from "react";
import type {
  DeviceRecord,
  DeviceStore,
  EgressBaseline,
  Observation,
  SweepFace,
} from "../types";
import { RiskEngine } from "../lib/RiskEngine";

export const LEDGER_KEY = "driftnet:devices";

function loadStore(): DeviceStore {
  try {
    const raw = localStorage.getItem(LEDGER_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as DeviceStore;
    if (!parsed || typeof parsed !== "object") return {};
    // Migrate records persisted before ipVersion existed (all were IPv4).
    for (const rec of Object.values(parsed)) {
      rec.ipVersion ??= 4;
    }
    return parsed;
  } catch {
    return {};
  }
}

function persist(store: DeviceStore): void {
  try {
    localStorage.setItem(LEDGER_KEY, JSON.stringify(store));
  } catch {
    /* quota / private mode — ledger stays in-memory for the session */
  }
}

export interface LedgerApi {
  devices: DeviceRecord[];
  /** Merge an observation into the ledger, returning the updated record. */
  record: (
    obs: Observation,
    egress?: EgressBaseline | null,
    sweep?: SweepFace[],
    now?: number,
  ) => DeviceRecord;
  /** Wipe the entire ledger. */
  clear: () => void;
  /** Look up a single record. */
  get: (ip: string) => DeviceRecord | undefined;
}

/**
 * useDeviceLedger — owns the localStorage-backed device store and exposes
 * mutation helpers. All risk scoring is delegated to RiskEngine; this hook is
 * purely persistence + merge bookkeeping.
 */
export function useDeviceLedger(): LedgerApi {
  const storeRef = useRef<DeviceStore>(loadStore());
  const [devices, setDevices] = useState<DeviceRecord[]>(() =>
    Object.values(storeRef.current),
  );

  // Keep the rendered list in sync with the underlying store.
  const sync = useCallback(() => {
    setDevices(Object.values(storeRef.current));
  }, []);

  // Reflect ledger changes made in other tabs.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === LEDGER_KEY) {
        storeRef.current = loadStore();
        sync();
      }
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, [sync]);

  const record = useCallback(
    (
      obs: Observation,
      egress: EgressBaseline | null = null,
      sweep: SweepFace[] = [],
      now: number = Date.now(),
    ): DeviceRecord => {
      const store = storeRef.current;
      const prior = store[obs.ip] ?? null;
      const assessment = RiskEngine.assess(obs, prior, egress, sweep, now);

      const next: DeviceRecord = {
        ip: obs.ip,
        ipClass: obs.ipClass,
        ipVersion: obs.ipVersion,
        firstSeen: prior?.firstSeen ?? now,
        lastSeen: now,
        seenCount: (prior?.seenCount ?? 0) + 1,
        portProfile: obs.portProfile,
        portSignature: obs.portSignature,
        fingerprintHash: obs.fingerprintHash,
        rttMs: obs.rttMs,
        riskScore: assessment.score,
        riskLevel: assessment.level,
        riskSignals: assessment.signals,
      };

      store[obs.ip] = next;
      persist(store);
      sync();
      return next;
    },
    [sync],
  );

  const clear = useCallback(() => {
    storeRef.current = {};
    persist(storeRef.current);
    sync();
  }, [sync]);

  const get = useCallback((ip: string) => storeRef.current[ip], []);

  return { devices, record, clear, get };
}
