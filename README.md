# driftnet

**Browser-based rogue device correlation engine.** Passive-style local network
intelligence built entirely on browser APIs — no server, no raw packets, no
elevated privileges. Everything runs client-side in a single React + Vite +
TypeScript page.

> ⚠️ Built for **authorized** use — security research, your own network, lab /
> CTF environments. The techniques here are heuristic browser side-channels,
> not a substitute for real packet-level tooling, and they only work against
> hosts and networks you are permitted to inspect.

## How it works

driftnet correlates devices across scans and flags anomalies using three
browser primitives:

1. **Discovery — WebRTC ICE candidate enumeration.** An `RTCPeerConnection`
   pointed at `stun.l.google.com:19302` with a throwaway data channel forces
   the browser to gather ICE candidates. Each candidate leaks a local host IP,
   which driftnet harvests (`src/lib/webrtc.ts`).
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
additive, weighted signals:

| Signal                                   | Weight | Tier driver |
| ---------------------------------------- | -----: | ----------- |
| New device (never seen)                  |    +35 | elevated    |
| Reappeared after >7 days absent          |    +30 | elevated    |
| Port profile changed since last seen     |    +45 | high        |
| Link-local address (169.254.0.0/16)      |    +25 | unusual     |
| Public IP leaked via WebRTC              |    +60 | critical    |
| Carrier-grade NAT (100.64.0.0/10)        |    +15 | unusual     |
| Remote-admin ports exposed (21 / 22)     |    +20 | elevated    |

Score → tier: `LOW` (<20), `MEDIUM` (20–44), `HIGH` (45–74), `CRITICAL` (≥75).

## Device ledger

Every discovered device is persisted to `localStorage` under the key
`driftnet:devices` as a keyed store. Each record holds: `ip`, `firstSeen`,
`lastSeen`, `seenCount`, `portProfile` (port + latency results),
`portSignature`, `fingerprintHash`, `rttMs`, and the computed `riskScore` /
`riskLevel` / `riskSignals`.

## UI

A dark, monospace, three-panel terminal layout:

- **Device ledger** — sortable table of all known devices (by risk, first/last
  seen, host).
- **Detail pane** — selected device's identity, history, signal breakdown, and
  port profile.
- **Scan log** — live output during enumeration.

Plus a **rescan** button, **clear log**, and **clear ledger** action.

## Architecture

```
src/
  hooks/
    useDeviceLedger.ts   localStorage persistence + merge bookkeeping
    useNetworkScanner.ts  WebRTC discovery + port-probe orchestration
  lib/
    RiskEngine.ts         stateless 0–100 risk scoring
    webrtc.ts             ICE candidate enumeration
    portProbe.ts          image-load timing port oracle
    fingerprint.ts        canvas/WebGL observer identity
    ipClass.ts            IPv4 range classification
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
- The port oracle is a heuristic — HTTPS upgrades, HSTS, and proxies all add
  noise. Treat results as signal, not ground truth.
- No backend means no cross-device sync; the ledger lives in one browser.
