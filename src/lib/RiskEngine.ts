import type {
  DeviceRecord,
  Observation,
  RiskAssessment,
  RiskLevel,
  RiskSignal,
} from "../types";

const DAY_MS = 24 * 60 * 60 * 1000;
const REAPPEAR_THRESHOLD_MS = 7 * DAY_MS;

/**
 * RiskEngine — computes a 0..100 risk score for a device from a set of
 * weighted anomaly signals. Stateless: given a fresh observation and the prior
 * ledger record (if any), it returns the assessment. The caller persists.
 *
 * Signal weights (additive, clamped to 100):
 *   - New device (never seen)              +35
 *   - Reappeared after >7 days absent      +30
 *   - Port profile changed since last seen +45  (high)
 *   - Link-local (169.254/16) address      +25
 *   - Public IP leaked via WebRTC          +60  (critical)
 *   - CGNAT address                        +15
 *   - Exposed remote-admin ports (21/22)   +20
 */
export class RiskEngine {
  static readonly REAPPEAR_THRESHOLD_MS = REAPPEAR_THRESHOLD_MS;

  /**
   * Assess a new observation against the prior record.
   * @param obs   freshly gathered observation
   * @param prior existing ledger record, or null if never seen
   * @param now   evaluation time (epoch ms), injectable for testing
   */
  static assess(
    obs: Observation,
    prior: DeviceRecord | null,
    now: number = Date.now(),
  ): RiskAssessment {
    const signals: RiskSignal[] = [];

    if (!prior) {
      signals.push({
        id: "new-device",
        label: "New device",
        weight: 35,
        detail: "First observation — no prior ledger entry.",
      });
    } else {
      const gap = now - prior.lastSeen;
      if (gap > REAPPEAR_THRESHOLD_MS) {
        const days = Math.floor(gap / DAY_MS);
        signals.push({
          id: "reappeared",
          label: "Reappeared after absence",
          weight: 30,
          detail: `Last seen ${days} day(s) ago (> 7-day threshold).`,
        });
      }
      if (prior.portSignature !== obs.portSignature) {
        signals.push({
          id: "port-drift",
          label: "Port profile changed",
          weight: 45,
          detail: `Open-port signature drifted: "${prior.portSignature}" → "${obs.portSignature}".`,
        });
      }
    }

    if (obs.ipClass === "link-local") {
      signals.push({
        id: "link-local",
        label: "Link-local address",
        weight: 25,
        detail: "169.254.0.0/16 (APIPA) — unusual on a managed network.",
      });
    }

    if (obs.ipClass === "public") {
      signals.push({
        id: "public-leak",
        label: "Public IP leaked via WebRTC",
        weight: 60,
        detail: "Routable address exposed — critical disclosure / possible rogue relay.",
      });
    }

    if (obs.ipClass === "cgnat") {
      signals.push({
        id: "cgnat",
        label: "Carrier-grade NAT address",
        weight: 15,
        detail: "100.64.0.0/10 — host behind CGNAT, unexpected on a LAN.",
      });
    }

    const adminPorts = obs.portProfile.filter(
      (p) => p.open && (p.port === 21 || p.port === 22),
    );
    if (adminPorts.length) {
      signals.push({
        id: "admin-ports",
        label: "Remote-admin ports exposed",
        weight: 20,
        detail: `Open: ${adminPorts.map((p) => p.port).join(", ")} (FTP/SSH).`,
      });
    }

    const raw = signals.reduce((sum, s) => sum + s.weight, 0);
    const score = Math.min(100, raw);

    return { score, level: RiskEngine.levelFor(score), signals };
  }

  /** Map a numeric score to a discrete risk tier. */
  static levelFor(score: number): RiskLevel {
    if (score >= 75) return "CRITICAL";
    if (score >= 45) return "HIGH";
    if (score >= 20) return "MEDIUM";
    return "LOW";
  }
}
