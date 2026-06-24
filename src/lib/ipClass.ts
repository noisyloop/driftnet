import type { IpClass } from "../types";

/**
 * Classify an IPv4 address into a range-based class.
 * mDNS / obfuscated candidates (e.g. *.local) are treated as unknown.
 */
export function classifyIp(ip: string): IpClass {
  // WebRTC may hand back an mDNS hostname instead of a raw address.
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

/** Human-readable label for an IP class. */
export function ipClassLabel(cls: IpClass): string {
  switch (cls) {
    case "private":
      return "RFC1918 private";
    case "link-local":
      return "link-local (APIPA)";
    case "public":
      return "public / routable";
    case "loopback":
      return "loopback";
    case "cgnat":
      return "carrier-grade NAT";
    default:
      return "unknown";
  }
}
