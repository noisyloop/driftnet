/**
 * Device discovery via WebRTC ICE candidate enumeration.
 *
 * Creating an RTCPeerConnection with a STUN server and a bogus data channel
 * forces the browser to gather ICE candidates. Each candidate's `address`
 * field exposes a local (host / srflx) IP — the classic WebRTC "leak" — which
 * we harvest passively. No media, no signaling, no remote peer.
 */

import type { IpVersion } from "../types";

export const STUN_URL = "stun:stun.l.google.com:19302";

/** A single address harvested from a candidate, tagged with its family. */
export interface IceAddress {
  address: string;
  /** 4 / 6, or null for mDNS `.local` hostnames that hide the raw IP. */
  family: IpVersion | null;
}

export interface IceDiscovery {
  /** Unique addresses seen across candidates (v4, v6, and mDNS hostnames). */
  addresses: IceAddress[];
  /** Raw candidate strings, for the scan log. */
  raw: string[];
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
// Hex groups and colons, optionally a `%zone` suffix or embedded v4 tail.
const IPV6 = /^[0-9a-f:]+(\.\d{1,3}){0,3}(%[\w.]+)?$/i;
const MDNS = /\.local$/i;

/** Tag a raw candidate address with its family (null ⇒ mDNS/hostname). */
export function tagAddress(address: string): IceAddress | null {
  if (MDNS.test(address)) return { address, family: null };
  if (IPV4.test(address)) return { address, family: 4 };
  if (address.includes(":") && IPV6.test(address)) {
    // Strip any zone index (fe80::1%eth0) so downstream matching is stable.
    return { address: address.split("%")[0], family: 6 };
  }
  return null;
}

function extractAddress(candidate: RTCIceCandidate): IceAddress | null {
  // Modern browsers expose `.address`; fall back to parsing the candidate
  // line, where the connection address is the 5th space-separated field.
  if (candidate.address) {
    const tagged = tagAddress(candidate.address);
    if (tagged) return tagged;
  }
  const field = candidate.candidate.split(" ")[4];
  return field ? tagAddress(field) : null;
}

/**
 * Gather ICE candidates and return discovered addresses — IPv4, IPv6, and
 * mDNS hostnames — each tagged with its address family.
 * Resolves when gathering completes or after `timeoutMs`.
 */
export function enumerateCandidates(
  onCandidate?: (raw: string, addr: IceAddress | null) => void,
  timeoutMs = 4000,
): Promise<IceDiscovery> {
  return new Promise((resolve) => {
    const seen = new Map<string, IceAddress>();
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
      resolve({ addresses: [...seen.values()], raw });
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
      const addr = extractAddress(ev.candidate);
      if (addr) seen.set(addr.address, addr);
      onCandidate?.(ev.candidate.candidate, addr);
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
