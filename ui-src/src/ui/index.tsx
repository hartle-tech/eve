import type { ReactNode, CSSProperties } from "react";
import { fuzzyScore } from "../format";

export function Card({ title, sub, children, action }: {
  title?: string; sub?: ReactNode; children?: ReactNode; action?: ReactNode;
}) {
  return (
    <section className="card">
      {title && (
        <header className="card-head">
          <span>{title}</span>
          {sub && <span className="sub">{sub}</span>}
          {action}
        </header>
      )}
      {children && <div className="card-body">{children}</div>}
    </section>
  );
}

export function Switch({ checked, onChange, label, disabled }: {
  checked: boolean; onChange: (v: boolean) => void; label: ReactNode; disabled?: boolean;
}) {
  return (
    <label className="switch">
      <input type="checkbox" checked={checked} disabled={disabled}
             onChange={(e) => onChange(e.target.checked)} />
      <span className="switch-track"><span className="switch-thumb" /></span>
      <span>{label}</span>
    </label>
  );
}

/// A ring. Used for anything that is "part of a whole" — disk usage, memory —
/// because a number alone never says whether it is a lot.
export function Donut({ value, max, size = 92, label, sub, tone = "var(--teal)" }: {
  value: number; max: number; size?: number; label: string; sub?: string; tone?: string;
}) {
  const r = size / 2 - 7;
  const c = 2 * Math.PI * r;
  const pct = max > 0 ? Math.min(1, Math.max(0, value / max)) : 0;
  return (
    <div className="donut" style={{ width: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
        <circle cx={size / 2} cy={size / 2} r={r} className="donut-track" />
        <circle cx={size / 2} cy={size / 2} r={r} className="donut-fill"
                stroke={tone}
                strokeDasharray={`${c * pct} ${c}`}
                transform={`rotate(-90 ${size / 2} ${size / 2})`} />
      </svg>
      <div className="donut-mid">
        <span className="donut-label num">{label}</span>
        {sub && <span className="donut-sub">{sub}</span>}
      </div>
    </div>
  );
}

/// A horizontal proportion bar, for a list of parts.
export function Meter({ fraction, tone }: { fraction: number; tone?: string }) {
  return (
    <span className="meter">
      <span className="meter-fill"
            style={{ width: `${Math.max(2, Math.min(100, fraction * 100))}%`, background: tone }} />
    </span>
  );
}

export function Pill({ children, tone }: { children: ReactNode; tone?: "good" | "warn" | "alert" }) {
  return <span className={`pill${tone ? ` pill-${tone}` : ""}`}>{children}</span>;
}

export function Btn({ children, onClick, kind = "ghost", disabled, size, style }: {
  children: ReactNode; onClick?: () => void;
  kind?: "primary" | "ghost" | "bare" | "danger";
  disabled?: boolean; size?: "sm"; style?: CSSProperties;
}) {
  return (
    <button type="button" style={style} disabled={disabled} onClick={onClick}
            className={`btn btn-${kind}${size ? ` btn-${size}` : ""}`}>
      {children}
    </button>
  );
}

export function Search({ value, onChange, placeholder }: {
  value: string; onChange: (v: string) => void; placeholder?: string;
}) {
  return (
    <div className="search">
      <svg viewBox="0 0 16 16"><circle cx="7" cy="7" r="4.5" /><path d="M10.5 10.5 14 14" /></svg>
      <input value={value} placeholder={placeholder} spellCheck={false}
             onChange={(e) => onChange(e.target.value)} />
      {value && <Btn kind="bare" size="sm" onClick={() => onChange("")}>Clear</Btn>}
    </div>
  );
}

export function Warn({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <p className="warn">
      <span className="warn-tri" aria-hidden>▲</span>
      <span>{children}</span>
      {action}
    </p>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

/// Something is happening and it is not instant.
///
/// Every disk operation in eve takes between a moment and several seconds, and
/// a screen that simply does not change is indistinguishable from one that
/// ignored the click. That is not a cosmetic problem: it is what makes people
/// click again, which is how the Disk view ended up navigating somewhere the
/// user had already left.
///
/// `label` says what is being waited on, because "Loading…" tells nobody
/// anything they did not already know.
export function Working({ label, inline }: { label: string; inline?: boolean }) {
  return (
    <div className={inline ? "working is-inline" : "working"} role="status" aria-live="polite">
      <span className="working-spin" aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

/// A row of placeholder bars, for a list whose shape is known before its
/// contents are. Steadier than a spinner when the wait is a list appearing.
export function Skeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="skeleton" aria-hidden="true">
      {Array.from({ length: rows }, (_, i) => (
        <div key={i} className="skeleton-row" style={{ animationDelay: `${i * 90}ms` }} />
      ))}
    </div>
  );
}

/// A settings section that disappears when it does not match the search.
///
/// The search has to reach the *whole* pane, not just one list — Apple's does,
/// and a search that silently ignores three of five cards is worse than none.
/// `terms` is everything a person might type to find this section, including
/// words that do not appear in its title.
export function Section({ query, terms, children }: {
  query: string;
  terms: string[];
  children: ReactNode;
}) {
  if (query.trim() && !terms.some((t) => fuzzyScore(query, t) !== null)) return null;
  return <>{children}</>;
}

/// One life signal: a label, a level, and a verdict carried by colour.
///
/// Full width by design. A ring is a dial you have to interpret and an island
/// in the middle of a wide window; a bar is a level you can compare across rows
/// because every one starts and ends in the same place.
export function Signal({ label, value, detail, fraction, tone }: {
  label: string;
  value: string;
  detail?: string;
  fraction: number;
  tone?: string;
}) {
  const pct = Math.max(0, Math.min(1, fraction)) * 100;
  return (
    <div className="signal-row">
      <div className="signal-head">
        <span className="signal-label">{label}</span>
        <span className="signal-value" style={{ color: tone }}>{value}</span>
      </div>
      <div className="signal-track" role="img" aria-label={`${label}: ${value}`}>
        <div className="signal-fill" style={{ width: `${pct}%`, background: tone }} />
      </div>
      {detail && <div className="signal-detail">{detail}</div>}
    </div>
  );
}
