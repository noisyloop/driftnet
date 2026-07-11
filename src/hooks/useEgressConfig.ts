import { useCallback, useEffect, useState } from "react";
import type { EgressBaseline } from "../types";

export const EGRESS_KEY = "driftnet:egress";

function normalize(raw: EgressBaseline | null): EgressBaseline | null {
  if (!raw || typeof raw !== "object") return null;
  const trim = (v: unknown) =>
    typeof v === "string" && v.trim() ? v.trim() : undefined;
  const next: EgressBaseline = {
    expectedIpv4: trim(raw.expectedIpv4),
    expectedIpv6: trim(raw.expectedIpv6),
    asn: trim(raw.asn),
    label: trim(raw.label),
  };
  return next.expectedIpv4 || next.expectedIpv6 || next.asn || next.label
    ? next
    : null;
}

function load(): EgressBaseline | null {
  try {
    const raw = localStorage.getItem(EGRESS_KEY);
    return raw ? normalize(JSON.parse(raw) as EgressBaseline) : null;
  } catch {
    return null;
  }
}

export interface EgressConfigApi {
  egress: EgressBaseline | null;
  /** Persist a new baseline (null / all-empty clears it). */
  setEgress: (next: EgressBaseline | null) => void;
}

/**
 * useEgressConfig — owns the user-declared expected-egress baseline,
 * persisted to localStorage under `driftnet:egress`. Purely local input;
 * nothing is ever verified against an external service.
 */
export function useEgressConfig(): EgressConfigApi {
  const [egress, setState] = useState<EgressBaseline | null>(load);

  // Reflect baseline changes made in other tabs.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === EGRESS_KEY) setState(load());
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const setEgress = useCallback((next: EgressBaseline | null) => {
    const clean = normalize(next);
    try {
      if (clean) localStorage.setItem(EGRESS_KEY, JSON.stringify(clean));
      else localStorage.removeItem(EGRESS_KEY);
    } catch {
      /* quota / private mode — baseline stays in-memory for the session */
    }
    setState(clean);
  }, []);

  return { egress, setEgress };
}
