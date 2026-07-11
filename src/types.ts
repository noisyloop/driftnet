// Shared domain types for driftnet.

/** Classification of an IP address based on its range. */
export type IpClass =
  | "private" // RFC1918 (10/8, 172.16/12, 192.168/16)
  | "link-local" // v4 169.254.0.0/16 (APIPA) or v6 fe80::/10
  | "public" // routable v4 or global-unicast v6 (2000::/3) — egress-scored
  | "loopback" // 127.0.0.0/8 or ::1
  | "cgnat" // 100.64.0.0/10 carrier-grade NAT
  | "ula" // v6 unique-local fc00::/7 — the v6 analogue of private
  | "obscured" // mDNS .local candidate hostname hiding the raw address
  | "unknown";

/** Address family of a discovered candidate. */
export type IpVersion = 4 | 6;

/**
 * User-declared expected egress (e.g. a VPN exit). All fields are
 * user-provided strings — never resolved against any external service.
 */
export interface EgressBaseline {
  expectedIpv4?: string;
  expectedIpv6?: string;
  /** Display-only; no ASN lookup or matching is performed. */
  asn?: string;
  /** Display-only, e.g. country / provider. */
  label?: string;
}

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

/** Per-signal severity tier (independent of the aggregate RiskLevel). */
export type SignalTier = "info" | "elevated" | "critical";

/** A single contributing signal in the risk computation. */
export interface RiskSignal {
  id: string;
  label: string;
  weight: number;
  detail: string;
  /** Severity tier for egress-aware signals; legacy signals omit it. */
  tier?: SignalTier;
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
  ipVersion: IpVersion;
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

/**
 * One face of the machine's connection seen during a sweep — the minimal
 * shape RiskEngine needs to correlate signals across a scan (e.g. spot a
 * global IPv6 alongside a tunneled IPv4).
 */
export interface SweepFace {
  ip: string;
  ipClass: IpClass;
  ipVersion: IpVersion;
}

/** A freshly observed device before it is merged into the ledger. */
export interface Observation extends SweepFace {
  rttMs: number;
  portProfile: PortResult[];
  portSignature: string;
  fingerprintHash: string;
}
