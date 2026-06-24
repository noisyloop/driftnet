import type { PortResult } from "../types";

/**
 * Port probing via image-load timing side-channel.
 *
 * The browser blocks raw sockets, but it *will* attempt to load an <img> from
 * an arbitrary host:port. The image never decodes (the service isn't an image
 * server), so we always end in `onerror` — but *when* the error fires leaks
 * information:
 *
 *   - A reachable host with an open port typically refuses/resets or returns
 *     non-image data quickly → fast error.
 *   - A closed port or filtered/dropped host hangs until the connection times
 *     out → slow error (or our own timeout).
 *
 * This is a heuristic timing oracle, not a real TCP connect. We classify a
 * port as "open" when the probe terminates faster than a threshold.
 */

/** Common ports worth profiling on a local device. */
export const COMMON_PORTS = [80, 443, 8080, 8443, 21, 22] as const;

/** Below this RTT (ms) we treat a terminated probe as a reachable port. */
const OPEN_THRESHOLD_MS = 1200;

function probePort(ip: string, port: number, timeoutMs: number): Promise<PortResult> {
  return new Promise((resolve) => {
    const start = performance.now();
    const img = new Image();
    let done = false;

    const settle = (open: boolean) => {
      if (done) return;
      done = true;
      const latencyMs = Math.round(performance.now() - start);
      img.onload = null;
      img.onerror = null;
      img.src = "about:blank";
      resolve({ port, open, latencyMs });
    };

    // https on 443/8443, http otherwise — best guess for the scheme.
    const scheme = port === 443 || port === 8443 ? "https" : "http";
    // Cache-buster keeps the browser from short-circuiting repeat probes.
    const bust = Math.random().toString(36).slice(2);

    img.onload = () => settle(true); // unexpected, but means the host answered
    img.onerror = () => {
      const latency = performance.now() - start;
      settle(latency < OPEN_THRESHOLD_MS);
    };

    window.setTimeout(() => settle(false), timeoutMs);

    try {
      img.src = `${scheme}://${ip}:${port}/driftnet-probe-${bust}.png`;
    } catch {
      settle(false);
    }
  });
}

/**
 * Probe a set of ports on a host. Ports are probed in parallel; the whole
 * sweep is bounded by `timeoutMs` per port.
 */
export async function probeHost(
  ip: string,
  ports: readonly number[] = COMMON_PORTS,
  timeoutMs = 2500,
): Promise<PortResult[]> {
  const results = await Promise.all(
    ports.map((p) => probePort(ip, p, timeoutMs)),
  );
  return results.sort((a, b) => a.port - b.port);
}

/**
 * Derive a stable signature from a port profile, used to detect drift between
 * scans. Only the set of open ports matters — latency jitter is ignored.
 */
export function portSignature(profile: PortResult[]): string {
  const open = profile
    .filter((p) => p.open)
    .map((p) => p.port)
    .sort((a, b) => a - b);
  return open.length ? open.join(",") : "none";
}

/** Best-effort RTT estimate: median latency of open ports, else min latency. */
export function estimateRtt(profile: PortResult[]): number {
  const open = profile.filter((p) => p.open).map((p) => p.latencyMs);
  const pool = open.length ? open : profile.map((p) => p.latencyMs);
  if (!pool.length) return 0;
  const sorted = [...pool].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2
    ? sorted[mid]
    : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
}
