// Shared domain types for driftnet.

/** Classification of an IP address based on its range. */
export type IpClass =
  | "private" // RFC1918 (10/8, 172.16/12, 192.168/16)
  | "link-local" // 169.254.0.0/16 — unusual, often APIPA / rogue
  | "public" // routable address leaked via WebRTC — critical
  | "loopback" // 127.0.0.0/8
  | "cgnat" // 100.64.0.0/10 carrier-grade NAT
  | "unknown";

/** Result of probing a single TCP port via image-load timing. */
export interface PortResult {
  port: number;
  /** True if the probe resolved/errored quickly enough to suggest the port is reachable. */
  open: boolean;
  /** Round-trip latency in milliseconds for the probe. */
  latencyMs: number;
}

/** Risk tiers derived from the numeric risk score. */
export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

/** A single contributing signal in the risk computation. */
export interface RiskSignal {
  id: string;
  label: string;
  weight: number;
  detail: string;
}

/** Output of the RiskEngine for a device. */
export interface RiskAssessment {
  score: number; // 0-100
  level: RiskLevel;
  signals: RiskSignal[];
}

/** A persisted device record in the ledger. */
export interface DeviceRecord {
  ip: string;
  ipClass: IpClass;
  firstSeen: number; // epoch ms
  lastSeen: number; // epoch ms
  seenCount: number;
  /** Most recent port probe profile. */
  portProfile: PortResult[];
  /** Stable signature derived from the port profile, used to detect drift. */
  portSignature: string;
  /** Canvas/WebGL fingerprint hash of the observing machine. */
  fingerprintHash: string;
  /** Estimated RTT to the device, in ms. */
  rttMs: number;
  riskScore: number;
  riskLevel: RiskLevel;
  /** Signals from the most recent assessment, kept for the detail pane. */
  riskSignals: RiskSignal[];
}

/** Keyed store persisted to localStorage. */
export type DeviceStore = Record<string, DeviceRecord>;

/** A live scan-log entry. */
export interface LogEntry {
  ts: number;
  level: "info" | "warn" | "crit" | "ok";
  msg: string;
}

/** A freshly observed device before it is merged into the ledger. */
export interface Observation {
  ip: string;
  ipClass: IpClass;
  rttMs: number;
  portProfile: PortResult[];
  portSignature: string;
  fingerprintHash: string;
}
