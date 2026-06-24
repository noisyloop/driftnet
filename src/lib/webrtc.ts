/**
 * Device discovery via WebRTC ICE candidate enumeration.
 *
 * Creating an RTCPeerConnection with a STUN server and a bogus data channel
 * forces the browser to gather ICE candidates. Each candidate's `address`
 * field exposes a local (host / srflx) IP — the classic WebRTC "leak" — which
 * we harvest passively. No media, no signaling, no remote peer.
 */

export const STUN_URL = "stun:stun.l.google.com:19302";

export interface IceDiscovery {
  /** Unique IP addresses seen across candidates. */
  ips: string[];
  /** Raw candidate strings, for the scan log. */
  raw: string[];
}

// IPv4 + IPv6 address extraction from a candidate line. We keep IPv4 only for
// classification; IPv6 / mDNS hosts are surfaced raw.
const IPV4 = /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/;

function extractAddress(candidate: RTCIceCandidate): string | null {
  // Modern browsers expose `.address`; fall back to parsing candidate string.
  if (candidate.address && IPV4.test(candidate.address)) {
    return candidate.address;
  }
  const m = candidate.candidate.match(IPV4);
  return m ? m[1] : null;
}

/**
 * Gather ICE candidates and return discovered IPv4 addresses.
 * Resolves when gathering completes or after `timeoutMs`.
 */
export function enumerateCandidates(
  onCandidate?: (raw: string, ip: string | null) => void,
  timeoutMs = 4000,
): Promise<IceDiscovery> {
  return new Promise((resolve) => {
    const ips = new Set<string>();
    const raw: string[] = [];
    let pc: RTCPeerConnection | null = null;
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      try {
        pc?.close();
      } catch {
        /* ignore */
      }
      resolve({ ips: [...ips], raw });
    };

    try {
      pc = new RTCPeerConnection({
        iceServers: [{ urls: STUN_URL }],
      });
    } catch {
      finish();
      return;
    }

    // A data channel is required to trigger ICE gathering without media.
    pc.createDataChannel("driftnet");

    pc.onicecandidate = (ev) => {
      if (!ev.candidate) {
        // null candidate => gathering complete.
        finish();
        return;
      }
      raw.push(ev.candidate.candidate);
      const ip = extractAddress(ev.candidate);
      if (ip) ips.add(ip);
      onCandidate?.(ev.candidate.candidate, ip);
    };

    pc.onicegatheringstatechange = () => {
      if (pc?.iceGatheringState === "complete") finish();
    };

    pc.createOffer()
      .then((offer) => pc?.setLocalDescription(offer))
      .catch(() => finish());

    window.setTimeout(finish, timeoutMs);
  });
}
