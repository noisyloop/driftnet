import type { IpClass, IpVersion } from "../types";

/** Address family of a candidate string (colon ⇒ IPv6). */
export function ipVersionOf(ip: string): IpVersion {
  return ip.includes(":") ? 6 : 4;
}

/**
 * Classify an IPv4 or IPv6 address into a range-based class.
 * mDNS `.local` candidate hostnames are flagged as "obscured".
 */
export function classifyIp(ip: string): IpClass {
  if (/\.local$/i.test(ip)) return "obscured";
  if (ip.includes(":")) return classifyIpv6(ip);
  return classifyIpv4(ip);
}

function classifyIpv4(ip: string): IpClass {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return "unknown";

  const o = ip.split(".").map((n) => parseInt(n, 10));
  if (o.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return "unknown";

  const [a, b] = o;

  if (a === 127) return "loopback";
  if (a === 169 && b === 254) return "link-local";

  // RFC1918 private ranges.
  if (a === 10) return "private";
  if (a === 172 && b >= 16 && b <= 31) return "private";
  if (a === 192 && b === 168) return "private";

  // RFC6598 carrier-grade NAT (100.64.0.0/10).
  if (a === 100 && b >= 64 && b <= 127) return "cgnat";

  return "public";
}

function classifyIpv6(ip: string): IpClass {
  const groups = parseIpv6(ip);
  if (!groups) return "unknown";

  // ::1 loopback.
  if (groups.every((g, i) => g === (i === 7 ? 1 : 0))) return "loopback";

  const first = groups[0];
  if ((first & 0xffc0) === 0xfe80) return "link-local"; // fe80::/10
  if ((first & 0xfe00) === 0xfc00) return "ula"; // fc00::/7 unique-local
  if ((first & 0xe000) === 0x2000) return "public"; // 2000::/3 global unicast

  return "unknown";
}

/**
 * Parse an IPv6 literal into its eight 16-bit groups. Handles `::`
 * compression, a `%zone` suffix, and an embedded IPv4 tail
 * (e.g. `::ffff:192.0.2.1`). Returns null if the literal is malformed.
 */
export function parseIpv6(ip: string): number[] | null {
  let s = ip.split("%")[0].toLowerCase();
  if (!s.includes(":")) return null;

  // Rewrite an embedded IPv4 tail as two hex groups.
  const v4 = s.match(/^(.+:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4) {
    const o = v4[2].split(".").map((n) => parseInt(n, 10));
    if (o.some((n) => n > 255)) return null;
    s = `${v4[1]}${(((o[0] << 8) | o[1]) >>> 0).toString(16)}:${(((o[2] << 8) | o[3]) >>> 0).toString(16)}`;
  }

  const halves = s.split("::");
  if (halves.length > 2) return null;

  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = 8 - head.length - tail.length;

  if (halves.length === 1 && head.length !== 8) return null;
  if (halves.length === 2 && fill < 1) return null;

  const groups: number[] = [];
  for (const part of [...head, ...Array(halves.length === 2 ? fill : 0).fill("0"), ...tail]) {
    if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
    groups.push(parseInt(part, 16));
  }
  return groups.length === 8 ? groups : null;
}

/** Human-readable label for an IP class. */
export function ipClassLabel(cls: IpClass): string {
  switch (cls) {
    case "private":
      return "RFC1918 private";
    case "link-local":
      return "link-local";
    case "public":
      return "public / routable";
    case "loopback":
      return "loopback";
    case "cgnat":
      return "carrier-grade NAT";
    case "ula":
      return "unique-local (ULA)";
    case "obscured":
      return "mDNS / obscured";
    default:
      return "unknown";
  }
}
