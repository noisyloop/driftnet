# driftnet

**Browser-based rogue device correlation engine.** Passive-style local network
intelligence built entirely on browser APIs — no server, no raw packets, no
elevated privileges. Everything runs client-side in a single React + Vite +
TypeScript page.

> ⚠️ Built for **authorized** use — security research, your own network, lab /
> CTF environments. The techniques here are heuristic browser side-channels,
> not a substitute for real packet-level tooling, and they only work against
> hosts and networks you are permitted to inspect.

## In plain English

Think of driftnet as a **privacy self-audit for your own device**, running
entirely inside a browser tab.

Whenever you're online, your machine has an identity on the network: the local
addresses it uses, and the public IP the internet sees you as. driftnet takes
attendance of *that* identity, notes what it saw, and remembers it between
visits. The next time you run it, it compares notes — *Is this the identity I
expect? Did an unexpected public address just show up? Are remote-admin ports
suddenly reachable? Did something reappear after a long absence?*

When something looks off, it raises a flag and gives it a risk score from calm
green to alarming red. Its sharpest trick is **VPN leak detection**: tell it the
exit IP you *expect* to be using, and it will confirm a clean tunnel — or scream
if a second, unexpected public IP or a native IPv6 address slips past it.

The clever part: it does all of this **without installing anything, without admin
rights, and without a server**. It repurposes ordinary browser features — the
same plumbing behind video calls, image loading, and graphics — to see the small
amount your own connection reveals. That makes it a lightweight, heuristic tool:
it makes educated guesses, not guarantees.

## What it can — and can't — do

The "rogue device correlation engine" tagline sounds bigger than the reality —
and the reality is the point.

**What it does**

- Takes attendance of *your own device's* network identity — the local addresses
  your machine hands out, and the public IP the internet sees you as.
- Remembers those across visits and flags what changed: a brand-new identity, an
  unexpected public IP, remote-admin ports that look reachable, an address that
  reappeared after a long gap.
- Checks whether your VPN is actually containing you: give it your expected exit
  (egress) IP and it confirms a clean tunnel — or flags a *second* unexpected
  public IP, or a native IPv6 address leaking past the tunnel.
- Runs entirely in a browser tab. Nothing installed, no admin rights, no server,
  no data leaves your machine.

**What it deliberately does NOT do**

- It does **not** scan your LAN or discover other people's devices. A browser
  can't read the router's client table or ARP-sweep the subnet — that needs
  privileges the browser denies. This is on purpose: share a network with
  housemates and driftnet never touches or exposes their gear. It only ever looks
  at itself.
- It is **not** antivirus / EDR. It never inspects processes, files, or behavior,
  so it can't detect malware directly. At most it offers circumstantial hints
  ("this identity's ports changed," "traffic is exiting somewhere you didn't
  configure") — not detection.
- It is **not** a replacement for packet-level tooling. For real network mapping
  you still want nmap / arp-scan. driftnet is the narrow, privilege-free,
  self-only complement to those — strongest exactly where nmap is awkward: no
  install, no root, no touching anyone else's devices.

## How it works

driftnet correlates a device's identity across scans and flags anomalies using
three browser primitives:

1. **Discovery — WebRTC ICE candidate enumeration.** An `RTCPeerConnection`
   pointed at `stun.l.google.com:19302` with a throwaway data channel forces
   the browser to gather ICE candidates. Each candidate leaks a local host IP or
   the public server-reflexive address, which driftnet harvests — **both IPv4 and
   IPv6** address families (`src/lib/webrtc.ts`, `src/lib/ipClass.ts`).
2. **Port profiling — image-load timing side-channel.** Raw sockets are
   blocked, but the browser will *try* to load an `<img>` from any `host:port`.
   The image never decodes, so we always hit `onerror` — but *how fast* the
   error fires is a timing oracle for reachability across common ports
   (80, 443, 8080, 8443, 21, 22) — see `src/lib/portProbe.ts`.
3. **Observer identity — canvas/WebGL fingerprint.** A canvas + WebGL renderer
   hash identifies the observing machine so ledgers from different analysts can
   be told apart (`src/lib/fingerprint.ts`).

## Risk model

Each device is scored 0–100 (`RiskEngine`, `src/lib/RiskEngine.ts`) from
additive, weighted signals. Public-IP scoring is **egress-aware**: a public IP
that matches your configured egress (see below) is expected and benign; the
alarm is for *unexpected* public addresses.

| Signal                                                     | Weight | Tier driver |
| ---------------------------------------------------------- | -----: | ----------- |
| New device (never seen)                                    |    +35 | elevated    |
| Reappeared after >7 days absent                            |    +30 | elevated    |
| Port profile changed since last seen                       |    +45 | high        |
| Link-local address (169.254.0.0/16)                        |    +25 | unusual     |
| Public IP matches configured egress (VPN confirmed)        |     +5 | info        |
| Public IP exposed — no egress baseline set                 |    +30 | elevated    |
| Public IP differs from configured egress (leak / relay)    |    +60 | critical    |
| Native IPv6 exposed while IPv4 tunneled (v6 leak)          |    +55 | critical    |
| Global IPv6 exposed — no egress baseline set               |    +35 | elevated    |
| Carrier-grade NAT (100.64.0.0/10)                          |    +15 | unusual     |
| Remote-admin ports exposed (21 / 22)                       |    +20 | elevated    |

Score → tier: `LOW` (<20), `MEDIUM` (20–44), `HIGH` (45–74), `CRITICAL` (≥75).

## Egress baseline

driftnet can hold an **expected egress** so VPN traffic is scored correctly.
Set your expected public IP (IPv4 and/or IPv6), plus optional ASN and a label
(all user-provided; no external lookups). It's persisted to `localStorage` under
`driftnet:egress`.

- Public IP **matches** the baseline → `VPN egress confirmed` (informational).
- Public IP present with **no** baseline → moderate "exposed" flag.
- Public IP **differs** from the baseline, or a global IPv6 leaks while IPv4 is
  tunneled → `CRITICAL`.

Leave it unset and driftnet still works — it just can't tell "my VPN, working"
from "an address I didn't expect," so it errs toward flagging.

## Device ledger

Every discovered identity is persisted to `localStorage` under the key
`driftnet:devices` as a keyed store. Each record holds: `ip`, `ipVersion`
(`4 | 6`), `firstSeen`, `lastSeen`, `seenCount`, `portProfile` (port + latency
results), `portSignature`, `fingerprintHash`, `rttMs`, and the computed
`riskScore` / `riskLevel` / `riskSignals`.

## UI

A dark, monospace, three-panel terminal layout:

- **Device ledger** — sortable table of all known identities (by risk, first/last
  seen, host), with v4/v6 entries visually distinguished.
- **Detail pane** — selected identity, history, signal breakdown, port profile,
  address family, and whether the public IP matched the configured egress.
- **Scan log** — live output during enumeration.

Plus a **rescan** button, an **egress-baseline editor**, **clear log**, and
**clear ledger** action.

## Architecture

```
src/
  hooks/
    useDeviceLedger.ts    localStorage persistence + merge bookkeeping
    useNetworkScanner.ts  WebRTC discovery + port-probe orchestration
    useEgressConfig.ts    expected-egress baseline persistence
  lib/
    RiskEngine.ts         stateless, egress-aware 0–100 risk scoring
    webrtc.ts             ICE candidate enumeration (IPv4 + IPv6)
    portProbe.ts          image-load timing port oracle
    fingerprint.ts        canvas/WebGL observer identity
    ipClass.ts            IPv4 + IPv6 range classification
    format.ts             timestamp / risk formatting helpers
  components/
    DeviceLedger.tsx  DetailPane.tsx  ScanLog.tsx
  App.tsx  main.tsx  types.ts  styles.css
```

## Develop

```bash
npm install
npm run dev      # vite dev server on :5173
npm run build    # typecheck + production build
npm run lint     # tsc --noEmit
```

## Limitations

- Modern browsers increasingly return **mDNS** (`*.local`) ICE candidates that
  hide the raw IP; those are surfaced but not probed.
- The port oracle is a heuristic — a fast `onerror` means *reachable* (which
  includes an active refusal), not necessarily *open*. HTTPS upgrades, HSTS, and
  proxies all add noise. Treat results as signal, not ground truth.
- The egress baseline is user-provided — driftnet doesn't verify your claimed
  exit IP against any external source (by design; zero backend).
- No backend means no cross-device sync; the ledger lives in one browser.
