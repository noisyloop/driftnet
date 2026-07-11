import type {
  DeviceRecord,
  EgressBaseline,
  Observation,
  RiskAssessment,
  RiskLevel,
  RiskSignal,
  SweepFace,
} from "../types";

const DAY_MS = 24 * 60 * 60 * 1000;
const REAPPEAR_THRESHOLD_MS = 7 * DAY_MS;

/**
 * RiskEngine — computes a 0..100 risk score for a device from a set of
 * weighted anomaly signals. Stateless: given a fresh observation, the prior
 * ledger record (if any), and the user's expected-egress baseline, it returns
 * the assessment. The caller persists.
 *
 * Signal weights (additive, clamped to 100):
 *   - New device (never seen)                        +35
 *   - Reappeared after >7 days absent                +30
 *   - Port profile changed since last seen           +45  (high)
 *   - Link-local address                             +25
 *   - Public IP matches configured egress            +5   (info)
 *   - Public IP, no egress baseline configured       +30  (elevated)
 *   - Public IP differs from configured egress       +60  (critical)
 *   - Global IPv6 while IPv4 tunneled, baseline set  +55  (critical)
 *   - Global IPv6 while IPv4 tunneled, no baseline   +35  (elevated)
 *   - CGNAT address                                  +15
 *   - Exposed remote-admin ports (21/22)             +20
 */
export class RiskEngine {
  static readonly REAPPEAR_THRESHOLD_MS = REAPPEAR_THRESHOLD_MS;

  /**
   * Assess a new observation against the prior record.
   * @param obs    freshly gathered observation
   * @param prior  existing ledger record, or null if never seen
   * @param egress user-configured expected egress, or null if unset
   * @param sweep  every face discovered in the same sweep (used to correlate
   *               a global IPv6 against a tunneled IPv4); may include obs
   * @param now    evaluation time (epoch ms), injectable for testing
   */
  static assess(
    obs: Observation,
    prior: DeviceRecord | null,
    egress: EgressBaseline | null = null,
    sweep: SweepFace[] = [],
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
        detail:
          obs.ipVersion === 6
            ? "fe80::/10 — expected on-link only, not routable."
            : "169.254.0.0/16 (APIPA) — unusual on a managed network.",
      });
    }

    if (obs.ipClass === "public") {
      signals.push(RiskEngine.publicIpSignal(obs, egress, sweep));
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

  /**
   * Egress-aware scoring of a public (routable v4 / global-unicast v6) face.
   * Exact-string matching against the user-declared expected egress IPs —
   * no external lookups, no fuzzy matching.
   */
  private static publicIpSignal(
    obs: SweepFace,
    egress: EgressBaseline | null,
    sweep: SweepFace[],
  ): RiskSignal {
    const expected =
      obs.ipVersion === 6 ? egress?.expectedIpv6 : egress?.expectedIpv4;
    const hasBaseline = Boolean(
      egress && (egress.expectedIpv4 || egress.expectedIpv6),
    );

    if (expected && obs.ip === expected) {
      return {
        id: "egress-confirmed",
        label: "VPN egress confirmed",
        weight: 5,
        tier: "info",
        detail: `Public ${obs.ipVersion === 6 ? "IPv6" : "IPv4"} matches the configured egress baseline.`,
      };
    }

    // The classic VPN failure: IPv4 rides the tunnel while native IPv6
    // slips out the side door. Only diagnosable for a v6 face when the
    // sweep also shows a tunneled v4 face.
    if (obs.ipVersion === 6 && RiskEngine.ipv4Tunneled(sweep, egress)) {
      return hasBaseline
        ? {
            id: "v6-leak",
            label: "Native IPv6 exposed while IPv4 tunneled (v6 leak)",
            weight: 55,
            tier: "critical",
            detail: `Global-unicast ${obs.ip} is outside the configured egress while IPv4 is tunneled.`,
          }
        : {
            id: "v6-exposed",
            label: "Global IPv6 exposed — verify VPN covers IPv6",
            weight: 35,
            tier: "elevated",
            detail: `Global-unicast ${obs.ip} seen alongside a tunneled IPv4 face; no egress baseline to confirm it.`,
          };
    }

    if (hasBaseline) {
      return {
        id: "public-unexpected",
        label: "Unexpected public IP — possible leak or rogue relay",
        weight: 60,
        tier: "critical",
        detail: `${obs.ip} does not match the configured egress${expected ? ` (${expected})` : ""}.`,
      };
    }

    return {
      id: "public-no-baseline",
      label: "Public IP exposed — no egress baseline set",
      weight: 30,
      tier: "elevated",
      detail: `${obs.ip} is routable; configure an egress baseline to distinguish VPN exit from leak.`,
    };
  }

  /**
   * True when the sweep's IPv4 face looks tunneled: every public v4 face
   * matches the configured v4 egress, and non-public faces (private / CGNAT /
   * link-local / loopback) never disqualify — i.e. no raw public v4 leaked.
   */
  private static ipv4Tunneled(
    sweep: SweepFace[],
    egress: EgressBaseline | null,
  ): boolean {
    const v4 = sweep.filter((f) => f.ipVersion === 4);
    if (!v4.length) return false;
    return v4.every(
      (f) =>
        f.ipClass !== "public" ||
        (Boolean(egress?.expectedIpv4) && f.ip === egress?.expectedIpv4),
    );
  }

  /** Map a numeric score to a discrete risk tier. */
  static levelFor(score: number): RiskLevel {
    if (score >= 75) return "CRITICAL";
    if (score >= 45) return "HIGH";
    if (score >= 20) return "MEDIUM";
    return "LOW";
  }
}
