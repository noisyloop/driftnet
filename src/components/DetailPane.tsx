import type { DeviceRecord } from "../types";
import { ipClassLabel } from "../lib/ipClass";
import { riskClass, stamp, timeAgo } from "../lib/format";

interface Props {
  device: DeviceRecord | null;
}

export function DetailPane({ device }: Props) {
  return (
    <div className="panel detail">
      <div className="panel-head">
        <span className="panel-title">device detail</span>
        {device && <span className="panel-meta mono">{device.ip}</span>}
      </div>
      <div className="panel-body">
        {!device ? (
          <div className="empty">select a device to inspect its history</div>
        ) : (
          <div className="detail-grid">
            <section>
              <h3>identity</h3>
              <dl>
                <dt>ip</dt>
                <dd className="mono">{device.ip}</dd>
                <dt>class</dt>
                <dd>{ipClassLabel(device.ipClass)}</dd>
                <dt>rtt est.</dt>
                <dd>{device.rttMs} ms</dd>
                <dt>observer fp</dt>
                <dd className="mono dim">{device.fingerprintHash}</dd>
              </dl>
            </section>

            <section>
              <h3>history</h3>
              <dl>
                <dt>first seen</dt>
                <dd title={stamp(device.firstSeen)}>
                  {stamp(device.firstSeen)} ({timeAgo(device.firstSeen)})
                </dd>
                <dt>last seen</dt>
                <dd title={stamp(device.lastSeen)}>
                  {stamp(device.lastSeen)} ({timeAgo(device.lastSeen)})
                </dd>
                <dt>seen count</dt>
                <dd>{device.seenCount}×</dd>
              </dl>
            </section>

            <section className="full">
              <h3>
                risk{" "}
                <span className={`risk-badge ${riskClass(device.riskLevel)}`}>
                  {device.riskLevel}
                </span>
                <span className="risk-num">{device.riskScore}/100</span>
              </h3>
              <div className="risk-bar">
                <div
                  className={`risk-bar-fill ${riskClass(device.riskLevel)}`}
                  style={{ width: `${device.riskScore}%` }}
                />
              </div>
              {device.riskSignals.length === 0 ? (
                <p className="dim">no anomaly signals — nominal device.</p>
              ) : (
                <ul className="signal-list">
                  {device.riskSignals.map((s) => (
                    <li key={s.id}>
                      <span className="signal-weight">+{s.weight}</span>
                      <span className="signal-label">{s.label}</span>
                      <span className="signal-detail dim">{s.detail}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>

            <section className="full">
              <h3>port profile</h3>
              <table className="port-table">
                <thead>
                  <tr>
                    <th>port</th>
                    <th>state</th>
                    <th>latency</th>
                  </tr>
                </thead>
                <tbody>
                  {device.portProfile.map((p) => (
                    <tr key={p.port} className={p.open ? "open" : "closed"}>
                      <td className="mono">{p.port}</td>
                      <td>{p.open ? "reachable" : "filtered"}</td>
                      <td className="mono">{p.latencyMs} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
