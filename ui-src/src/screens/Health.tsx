import { useEffect, useState } from "react";
import { api, type BoostResult, type MemoryReport, type Status } from "../tauri";
import { bytes, duration } from "../format";
import { Btn, Card, Empty, Meter, Pill, Signal, Warn, Working } from "../ui";
import { ContextMenu, useContextMenu } from "../ContextMenu";

const HUES = ["var(--hue-teal)", "var(--hue-blue)", "var(--hue-purple)", "var(--hue-orange)", "var(--hue-pink)"];

/// Memory, and the two buttons that actually change it.
///
/// The panel every Mac cleaner has, written to be honest about what it does.
/// Their version shows one number and one **Free Up** button; the number is
/// the rise in free pages after `purge`, which is a cache being thrown away,
/// not memory being recovered. Here the mechanism is named, the cost is on the
/// row next to the button, and the result is the *measured* before-and-after —
/// including when it is nothing, which is most of the time.
function Memory() {
  const [m, setM] = useState<MemoryReport | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [last, setLast] = useState<BoostResult | null>(null);
  const [armed, setArmed] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = () => api.memoryReport().then(setM).catch(() => {});
  useEffect(() => { load(); }, []);

  const run = async (key: string, unsafeMode: boolean) => {
    // The unsafe one degrades the rest of the machine to move a number, so it
    // asks twice. The safe one does not — a confirmation for something
    // reversible only teaches people to click through confirmations.
    if (unsafeMode && armed !== key) { setArmed(key); return; }
    setArmed(null);
    setBusy(key);
    setErr(null);
    try {
      const r = await api.runBoost(key, true);
      setLast(r);
      await load();
    } catch (e) {
      setLast(null);
      setErr(String(e));
    } finally {
      setBusy(null);
    }
  };

  if (!m) return <Card title="Memory"><Working label="Reading memory…" /></Card>;

  const s = m.snapshot;
  const usedFraction = s.total ? (s.total - s.free) / s.total : 0;
  const pressureTone = s.pressure === "critical" ? "var(--alert)"
    : s.pressure === "warning" ? "var(--warn)" : "var(--good)";

  return (
    <Card
      title="Memory"
      sub={<>pressure <span style={{ color: pressureTone }}>{s.pressure}</span></>}
      action={<Btn kind="bare" size="sm" onClick={load}>Refresh</Btn>}
    >
      <div className="signals-grid">
        <Signal label="In use" value={bytes(s.total - s.free)}
                detail={`of ${bytes(s.total)} · ${bytes(s.wired)} wired, ${bytes(s.compressed)} compressed`}
                fraction={usedFraction}
                tone={usedFraction > 0.95 ? "var(--alert)" : "var(--hue-blue)"} />
        <Signal label="Disk cache" value={bytes(s.file_backed + s.speculative)}
                detail="files kept in memory so re-reading them is free — this is what a “free up RAM” button throws away"
                fraction={s.total ? (s.file_backed + s.speculative) / s.total : 0}
                tone="var(--hue-teal)" />
        {s.swap_total > 0 && (
          <Signal label="Swap" value={bytes(s.swap_used)}
                  detail={`of ${bytes(s.swap_total)} — pages pushed to disk`}
                  fraction={s.swap_used / s.swap_total}
                  tone={s.swap_used > 2 * 1024 ** 3 ? "var(--alert)"
                     : s.swap_used > 0 ? "var(--warn)" : "var(--hue-purple)"} />
        )}
      </div>

      {err && <Warn>{err}</Warn>}

      {last && (
        <p className="card-note" data-testid="boost-result" style={{ marginTop: 10 }}>
          {!last.ok
            ? `Nothing was done: ${last.detail ?? "macOS refused"}.`
            : Math.abs(last.freed) < 100 * 1024 ** 2
              ? `Ran. Free memory moved by ${bytes(Math.abs(last.freed))} — that is noise, not a result. Your Mac was already managing its memory.`
              : last.freed > 0
                ? `Free memory went up by ${bytes(last.freed)}. It will fill again as the cache refills.`
                : `Free memory went down by ${bytes(-last.freed)} — the machine kept working while eve measured.`}
        </p>
      )}

      <div className="rows" style={{ margin: "10px -16px 0" }}>
        {m.boosts.map((b) => (
          <div key={b.key} className="rw" style={{ gridTemplateColumns: "1fr auto" }}>
            <div style={{ minWidth: 0 }}>
              <div className="rw-name">
                {b.title}{" "}
                <Pill tone={b.mode === "unsafe" ? "alert" : "good"}>{b.mode}</Pill>
                {b.needs_root && <span className="rw-sub"> · needs your password</span>}
              </div>
              <div className="rw-sub">{b.detail}</div>
              <div className="rw-sub" style={{ color: b.mode === "unsafe" ? "var(--alert)" : undefined }}>
                {b.caveat}
              </div>
            </div>
            <Btn
              kind={armed === b.key ? "danger" : "ghost"}
              size="sm"
              disabled={busy !== null}
              onClick={() => run(b.key, b.mode === "unsafe")}
            >
              {busy === b.key ? "Working…" : armed === b.key ? "Confirm" : "Run"}
            </Btn>
          </div>
        ))}
      </div>

      {m.fixed_costs.length > 0 && (
        <div className="rows" style={{ margin: "10px -16px 0" }}>
          {m.fixed_costs.map((c) => (
            <div key={c.path} className="rw" style={{ gridTemplateColumns: "1fr 90px" }}>
              <div style={{ minWidth: 0 }}>
                <div className="rw-name truncate">{c.path}</div>
                <div className="rw-sub">{c.why}</div>
              </div>
              <div className="rw-size">{bytes(c.bytes)}</div>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

/// Life signals, read left to right.
///
/// Rings were the wrong instrument. A donut is a dial you have to interpret,
/// each one an island in the middle of a wide window, and four of them in a row
/// wasted the horizontal space while making the reader compare arcs. A full
/// width bar is a *level*: how full, at a glance, on a scale you can compare
/// across rows because they all start and end in the same place. Colour carries
/// the verdict so the number never has to be interpreted at all.
export function Health() {
  const menu = useContextMenu();
  const [s, setS] = useState<Status | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = () => api.status().then((v) => alive && setS(v)).catch((e) => alive && setErr(String(e)));
    tick();
    const id = setInterval(tick, 4000);
    return () => { alive = false; clearInterval(id); };
  }, []);

  if (err) return <div className="scroll"><Card><p className="card-note">{err}</p></Card></div>;
  if (!s) return <div className="scroll"><Empty>Collecting…</Empty></div>;

  const memPct = s.mem_total ? s.mem_used / s.mem_total : 0;
  const cpuTone = s.cpu_usage > 85 ? "var(--alert)" : s.cpu_usage > 60 ? "var(--warn)" : "var(--teal)";
  const memTone = memPct > 0.9 ? "var(--alert)" : memPct > 0.75 ? "var(--warn)" : "var(--hue-blue)";

  return (
    <div className="scroll">
      <div className="page-head">
        <h1>Health</h1>
        <p>{s.host} · {s.os} · up {duration(s.uptime_secs)}</p>
      </div>

      <Card title="Right now">
        <div className="signals-grid">
          <Signal label="CPU" value={`${Math.round(s.cpu_usage)}%`}
                  detail={`${s.cpu_count} cores`}
                  fraction={s.cpu_usage / 100} tone={cpuTone} />
          <Signal label="Memory" value={bytes(s.mem_used)}
                  detail={`of ${bytes(s.mem_total)}`}
                  fraction={memPct} tone={memTone} />
          {s.swap_total > 0 && (
            <Signal label="Swap" value={bytes(s.swap_used)}
                    detail={s.swap_used > 0 ? "memory is under pressure" : "not in use"}
                    fraction={s.swap_used / s.swap_total}
                    tone={s.swap_used > 2 * 1024 ** 3 ? "var(--alert)"
                       : s.swap_used > 0 ? "var(--warn)" : "var(--hue-purple)"} />
          )}
          <Signal label="Load" value={s.load[0].toFixed(2)}
                  detail={`${s.load[1].toFixed(2)} · ${s.load[2].toFixed(2)} over 5 and 15 min`}
                  fraction={Math.min(1, s.load[0] / Math.max(1, s.cpu_count))}
                  tone={s.load[0] > s.cpu_count ? "var(--alert)"
                     : s.load[0] > s.cpu_count * 0.7 ? "var(--warn)" : "var(--hue-teal)"} />
        </div>
      </Card>

      <Memory />

      <Card title="Volumes">
        <div className="signals-grid">
          {s.volumes.map((v) => {
            const used = v.total ? (v.total - v.available) / v.total : 0;
            const tone = v.available < 5 * 1024 ** 3 ? "var(--alert)"
              : v.available < 15 * 1024 ** 3 ? "var(--warn)" : "var(--good)";
            return (
              <div key={v.mount} onContextMenu={menu.onContextMenu(v.mount)}>
                <Signal label={v.mount} value={`${bytes(v.available)} free`}
                        detail={`${bytes(v.total)} total`}
                        fraction={used} tone={tone} />
              </div>
            );
          })}
        </div>
      </Card>

      <Card title="Findings">
        <div className="rows" style={{ margin: "0 -16px" }}>
          {!s.health.length && <Empty>Nothing to report.</Empty>}
          {s.health.map((f) => (
            <div key={f.subject} className="rw" style={{ gridTemplateColumns: "10px 1fr auto" }}>
              <span className="dot" style={{
                background: f.level === "critical" ? "var(--alert)"
                  : f.level === "warn" ? "var(--warn)" : "var(--good)",
              }} />
              <div style={{ minWidth: 0 }}>
                <div className="rw-name">{f.subject}</div>
                <div className="rw-sub truncate">{f.detail}</div>
              </div>
              <Pill tone={f.level === "critical" ? "alert" : f.level === "warn" ? "warn" : "good"}>
                {f.level}
              </Pill>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Busiest processes">
        <div className="rows" style={{ margin: "0 -16px" }}>
          {s.top_processes.slice(0, 6).map((p, i) => (
            <div key={p.pid} className="rw" style={{ gridTemplateColumns: "1fr 150px 70px 90px" }}
                 onContextMenu={menu.onProcessMenu(p.pid, p.name, p.exe ?? null)}>
              <div className="rw-name truncate">{p.name}</div>
              <Meter fraction={Math.min(1, p.cpu / 100)} tone={HUES[i % HUES.length]} />
              <div className="rw-size">{p.cpu.toFixed(1)}%</div>
              <div className="rw-size">{bytes(p.memory)}</div>
            </div>
          ))}
        </div>
      </Card>

      <ContextMenu target={menu.target} onClose={menu.close} />
    </div>
  );
}
