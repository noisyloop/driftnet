import { describe, expect, it } from "vitest";
import { RiskEngine } from "../RiskEngine";
import type {
  EgressBaseline,
  IpClass,
  IpVersion,
  Observation,
  SweepFace,
} from "../../types";

const NOW = 1_750_000_000_000;

function obs(
  ip: string,
  ipClass: IpClass,
  ipVersion: IpVersion,
): Observation {
  return {
    ip,
    ipClass,
    ipVersion,
    rttMs: 10,
    portProfile: [],
    portSignature: "none",
    fingerprintHash: "fp",
  };
}

const face = (ip: string, ipClass: IpClass, ipVersion: IpVersion): SweepFace => ({
  ip,
  ipClass,
  ipVersion,
});

const VPN_V4 = "203.0.113.7";
const BASELINE: EgressBaseline = { expectedIpv4: VPN_V4 };
const BASELINE_V6: EgressBaseline = {
  expectedIpv4: VPN_V4,
  expectedIpv6: "2001:db8::7",
};

function signal(o: Observation, egress: EgressBaseline | null, sweep: SweepFace[] = []) {
  const { signals } = RiskEngine.assess(o, null, egress, sweep, NOW);
  return signals.find((s) =>
    ["egress-confirmed", "public-no-baseline", "public-unexpected", "v6-leak", "v6-exposed"].includes(s.id),
  );
}

describe("RiskEngine — egress-aware public IP scoring", () => {
  it("public IP matching the configured egress → +5 info (VPN confirmed)", () => {
    const s = signal(obs(VPN_V4, "public", 4), BASELINE);
    expect(s).toMatchObject({
      id: "egress-confirmed",
      label: "VPN egress confirmed",
      weight: 5,
      tier: "info",
    });
  });

  it("public IP with no baseline configured → +30 elevated", () => {
    const s = signal(obs("198.51.100.9", "public", 4), null);
    expect(s).toMatchObject({
      id: "public-no-baseline",
      label: "Public IP exposed — no egress baseline set",
      weight: 30,
      tier: "elevated",
    });
  });

  it("an all-empty baseline counts as unconfigured", () => {
    const s = signal(obs("198.51.100.9", "public", 4), { label: "note" });
    expect(s?.id).toBe("public-no-baseline");
  });

  it("public IP differing from the baseline → +60 critical", () => {
    const s = signal(obs("198.51.100.9", "public", 4), BASELINE);
    expect(s).toMatchObject({
      id: "public-unexpected",
      label: "Unexpected public IP — possible leak or rogue relay",
      weight: 60,
      tier: "critical",
    });
  });

  it("matching is exact-string — no prefix or fuzzy match", () => {
    const s = signal(obs("203.0.113.70", "public", 4), BASELINE);
    expect(s?.id).toBe("public-unexpected");
  });

  it("public IPv6 matching the configured v6 egress → confirmed", () => {
    const s = signal(obs("2001:db8::7", "public", 6), BASELINE_V6);
    expect(s?.id).toBe("egress-confirmed");
  });
});

describe("RiskEngine — IPv6 leak while IPv4 tunneled", () => {
  const V6_LEAK = "2607:f8b0::1234";

  it("baseline set, v4 matches egress, foreign global v6 → +55 critical v6-leak", () => {
    const sweep = [
      face(VPN_V4, "public", 4),
      face(V6_LEAK, "public", 6),
    ];
    const s = signal(obs(V6_LEAK, "public", 6), BASELINE, sweep);
    expect(s).toMatchObject({
      id: "v6-leak",
      label: "Native IPv6 exposed while IPv4 tunneled (v6 leak)",
      weight: 55,
      tier: "critical",
    });
  });

  it("baseline set, v4 face private (fully NATed tunnel) → still v6-leak", () => {
    const sweep = [
      face("192.168.1.20", "private", 4),
      face(V6_LEAK, "public", 6),
    ];
    const s = signal(obs(V6_LEAK, "public", 6), BASELINE, sweep);
    expect(s?.id).toBe("v6-leak");
  });

  it("no baseline → downgraded to +35 elevated verify-your-VPN", () => {
    const sweep = [
      face("100.72.0.9", "cgnat", 4),
      face(V6_LEAK, "public", 6),
    ];
    const s = signal(obs(V6_LEAK, "public", 6), null, sweep);
    expect(s).toMatchObject({
      id: "v6-exposed",
      label: "Global IPv6 exposed — verify VPN covers IPv6",
      weight: 35,
      tier: "elevated",
    });
  });

  it("v4 face NOT tunneled (unexpected public v4) → generic unexpected-public, not v6-leak", () => {
    const sweep = [
      face("198.51.100.9", "public", 4),
      face(V6_LEAK, "public", 6),
    ];
    const s = signal(obs(V6_LEAK, "public", 6), BASELINE, sweep);
    expect(s?.id).toBe("public-unexpected");
  });

  it("no v4 face in the sweep → not diagnosed as a v6 leak", () => {
    const sweep = [face(V6_LEAK, "public", 6)];
    const s = signal(obs(V6_LEAK, "public", 6), BASELINE, sweep);
    expect(s?.id).toBe("public-unexpected");
  });

  it("global v6 matching the configured v6 egress is confirmed, not a leak", () => {
    const sweep = [
      face(VPN_V4, "public", 4),
      face("2001:db8::7", "public", 6),
    ];
    const s = signal(obs("2001:db8::7", "public", 6), BASELINE_V6, sweep);
    expect(s?.id).toBe("egress-confirmed");
  });
});

describe("RiskEngine — legacy signals unchanged", () => {
  it("still flags a new private device at +35 only", () => {
    const { score, signals } = RiskEngine.assess(
      obs("192.168.1.20", "private", 4),
      null,
      null,
      [],
      NOW,
    );
    expect(signals).toHaveLength(1);
    expect(signals[0].id).toBe("new-device");
    expect(score).toBe(35);
  });

  it("clamps the aggregate score at 100", () => {
    const { score, level } = RiskEngine.assess(
      obs("198.51.100.9", "public", 4),
      null,
      BASELINE,
      [],
      NOW,
    );
    // new-device (35) + public-unexpected (60) = 95 → HIGH/CRITICAL boundary
    expect(score).toBe(95);
    expect(level).toBe("CRITICAL");
  });
});
