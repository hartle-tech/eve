import type { CleanReport, Status } from "../tauri";
import { bytes } from "../format";
import { Btn, Card, Meter, Skeleton, Working } from "../ui";

const HUES = [
  "var(--hue-teal)", "var(--hue-blue)", "var(--hue-purple)",
  "var(--hue-orange)", "var(--hue-pink)", "var(--hue-indigo)",
];

/// How much trouble the disk is in.
///
/// The old screen laid out four equal tiles — disk, reclaimable, memory, CPU —
/// so a machine with 10 GB left looked exactly like a machine with 200 GB, and
/// "CPU 97%" carried the same visual weight as "you are about to run out of
/// room". Everything was the same size, so nothing was urgent.
///
/// Severity is computed once, here, and everything on the screen reads from it.
function severity(free: number, cap: number): "critical" | "low" | "calm" {
  if (!cap) return "calm";
  const share = free / cap;
  // Both, because they fail differently: a 256 GB laptop in trouble and a 4 TB
  // drive in trouble do not look alike as a percentage, and 8 GB free breaks
  // macOS whatever the disk's size.
  if (free < 10 * 1024 ** 3 || share < 0.08) return "critical";
  if (free < 25 * 1024 ** 3 || share < 0.15) return "low";
  return "calm";
}

export function Dashboard({ report, status, busy, freedLast, onClean, onGo }: {
  report: CleanReport | null;
  status: Status | null;
  busy: boolean;
  /// What the last cleanup actually freed, or null if none has run.
  ///
  /// Shown because the figure in the headline is *what is left*, and after a
  /// successful run that is a smaller number with nothing to say it went down
  /// on purpose. A result the screen never mentions is why a cleanup that
  /// worked read as one that did nothing.
  freedLast: number | null;
  onClean: () => void;
  onGo: (view: string) => void;
}) {
  const total = report
    ? report.categories.reduce(
        (s, c) => s + c.reports.reduce((a, r) => a + (r.outcome?.bytes ?? 0), 0), 0)
    : 0;

  const vol = status?.volumes?.[0];
  const free = report?.free_after ?? vol?.available ?? 0;
  const cap = vol?.total ?? 0;
  const used = cap ? Math.max(0, cap - free) : 0;
  const level = severity(free, cap);

  // The reclaimable slice is drawn *out of* the used bar, because that is what
  // it is: space eve can hand back. It is the one thing this dashboard can
  // show that a generic system monitor cannot.
  const reclaimable = Math.min(total, used);
  const pct = (n: number) => (cap ? (n / cap) * 100 : 0);

  const top = report
    ? report.categories
        .map((c) => ({
          title: c.title,
          bytes: c.reports.reduce((a, r) => a + (r.outcome?.bytes ?? 0), 0),
        }))
        .filter((c) => c.bytes > 0)
        .sort((a, b) => b.bytes - a.bytes)
        .slice(0, 6)
    : [];
  const biggest = top[0]?.bytes || 1;

  const headline =
    level === "critical" ? "Your disk is nearly full"
    : level === "low" ? "Your disk is filling up"
    : "There is room to spare";

  const freedNote = freedLast && freedLast > 0
    ? `Last cleanup freed ${bytes(freedLast)}. `
    : "";
  const subline = busy && !report
    ? "Looking through your caches, logs and scratch space…"
    : total > 0
      ? `${freedNote}eve can give back ${bytes(total)} of it.`
      : level === "calm"
        ? `${freedNote}Nothing worth reclaiming right now.`
        : `${freedNote}eve found nothing to reclaim — the space is in your own files.`;

  const alarming = status?.health?.filter((h) => h.level !== "ok") ?? [];

  return (
    <div className="scroll">
      {/* The one loud thing on the screen. Its whole register changes with
          severity: on a healthy disk this is a quiet band with a number in it,
          and it only raises its voice when raising it is warranted. */}
      <section className={`capacity is-${level}`}>
        <div className="capacity-head">
          <div>
            <p className="capacity-eyebrow">{cap ? `${bytes(cap)} volume` : "Disk"}</p>
            <h1 className="capacity-headline">{headline}</h1>
            <p className="capacity-sub">{subline}</p>
          </div>
          <div className="capacity-figure">
            <output className="capacity-free">{cap ? bytes(free) : "—"}</output>
            <span className="capacity-free-label">free</span>
            {busy && (
              <div style={{ marginTop: 6 }}>
                <Working label={report ? "Rescanning…" : "Scanning…"} inline />
              </div>
            )}
          </div>
        </div>

        <div className="capacity-bar" role="img"
             aria-label={`${bytes(free)} free of ${bytes(cap)}, ${bytes(total)} reclaimable`}>
          <div className="cap-seg cap-used" style={{ width: `${pct(used - reclaimable)}%` }} />
          <div className="cap-seg cap-reclaim" style={{ width: `${pct(reclaimable)}%` }} />
          <div className="cap-seg cap-free" style={{ width: `${pct(free)}%` }} />
        </div>

        <div className="capacity-legend">
          <span><i className="dot dot-used" />In use {bytes(used - reclaimable)}</span>
          {reclaimable > 0 && (
            <span><i className="dot dot-reclaim" />Reclaimable {bytes(reclaimable)}</span>
          )}
          <span><i className="dot dot-free" />Free {bytes(free)}</span>
          <span className="grow" />
          <Btn kind={level === "calm" ? "ghost" : "primary"}
               disabled={busy || total === 0} onClick={onClean}>
            {total > 0 ? `Clean up ${bytes(total)}` : "Nothing to clean"}
          </Btn>
        </div>
      </section>

      {alarming.length > 0 && (
        <div className="signals">
          {alarming.slice(0, 3).map((h) => (
            <div key={h.subject} className={`signal is-${h.level}`}>
              <span className="signal-subject">{h.subject}</span>
              <span className="signal-detail">{h.detail}</span>
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: 14 }}>
        <Card title="Where the space is"
              action={<Btn kind="bare" size="sm" onClick={() => onGo("clean")}>See all</Btn>}>
          <div className="rows" style={{ margin: "0 -16px" }}>
            {!top.length && busy && <Skeleton rows={4} />}
            {!top.length && !busy && <p className="empty">Nothing found.</p>}
            {top.map((c, i) => (
              <div key={c.title} className="rw" style={{ gridTemplateColumns: "1fr 190px 92px" }}>
                <div className="rw-name truncate">{c.title}</div>
                <Meter fraction={c.bytes / biggest} tone={HUES[i % HUES.length]} />
                <div className="rw-size">{bytes(c.bytes)}</div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Deliberately the quietest thing here. It is context, not news — and
          giving it tile-sized weight is what flattened the old screen. */}
      <div className="vitals">
        <span><b>{status ? bytes(status.mem_used) : "—"}</b> memory of {status ? bytes(status.mem_total) : "—"}</span>
        <span><b>{status ? `${Math.round(status.cpu_usage)}%` : "—"}</b> CPU across {status?.cpu_count ?? "—"} cores</span>
        {status?.swap_used ? <span><b>{bytes(status.swap_used)}</b> swap in use</span> : null}
        <span className="grow" />
        <button className="vitals-link" onClick={() => onGo("health")}>Health</button>
      </div>
    </div>
  );
}
