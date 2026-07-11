import type { EgressBaseline } from "../types";

interface Props {
  egress: EgressBaseline | null;
  onChange: (next: EgressBaseline | null) => void;
  onClose: () => void;
}

/**
 * EgressPanel — compact editor for the expected-egress baseline. All fields
 * are user-provided strings persisted to localStorage (`driftnet:egress`);
 * nothing is looked up externally. ASN / label are display-only.
 */
export function EgressPanel({ egress, onChange, onClose }: Props) {
  const set = (patch: Partial<EgressBaseline>) =>
    onChange({ ...egress, ...patch });

  return (
    <div className="egress-panel">
      <div className="egress-head">
        <span className="panel-title">egress baseline</span>
        <span className="panel-meta">
          expected VPN exit — exact match, no external lookups
        </span>
        <button className="btn btn-close" onClick={onClose}>
          ✕
        </button>
      </div>
      <div className="egress-fields">
        <label>
          <span>expected ipv4</span>
          <input
            className="input mono"
            placeholder="e.g. 203.0.113.7"
            value={egress?.expectedIpv4 ?? ""}
            onChange={(e) => set({ expectedIpv4: e.target.value })}
            spellCheck={false}
          />
        </label>
        <label>
          <span>expected ipv6</span>
          <input
            className="input mono"
            placeholder="e.g. 2001:db8::7"
            value={egress?.expectedIpv6 ?? ""}
            onChange={(e) => set({ expectedIpv6: e.target.value })}
            spellCheck={false}
          />
        </label>
        <label>
          <span>asn (display)</span>
          <input
            className="input mono"
            placeholder="e.g. AS64496"
            value={egress?.asn ?? ""}
            onChange={(e) => set({ asn: e.target.value })}
            spellCheck={false}
          />
        </label>
        <label>
          <span>label (display)</span>
          <input
            className="input"
            placeholder="e.g. mullvad-ch"
            value={egress?.label ?? ""}
            onChange={(e) => set({ label: e.target.value })}
            spellCheck={false}
          />
        </label>
        <button
          className="btn btn-danger"
          onClick={() => onChange(null)}
          disabled={!egress}
        >
          clear
        </button>
      </div>
    </div>
  );
}
