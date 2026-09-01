import { useEffect, useMemo, useRef, useState } from "react";
import { api, type JournalEntry } from "../tauri";
import { bytes, homeRelative, when } from "../format";
import { Btn, Card, Empty, Pill, Search } from "../ui";

const ROW = 46;
const PAGE = 2000;

/// Name, path, size, date — searchable, and virtualised because the journal
/// is past thirteen thousand entries on a machine that has run eve for a
/// fortnight. Rendering all of them is what made this view feel broken.
export function History() {
  const [rows, setRows] = useState<JournalEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [q, setQ] = useState("");
  const [scrollTop, setScrollTop] = useState(0);
  const [height, setHeight] = useState(600);
  const box = useRef<HTMLDivElement>(null);
  const [armed, setArmed] = useState(false);
  const [note, setNote] = useState<string | null>(null);

  const load = () =>
    api.history(0, PAGE).then((p) => { setRows(p.entries); setTotal(p.total); }).catch(() => {});
  useEffect(() => { load(); }, []);

  // Two presses, like every other destructive action in eve. The journal is
  // the only record of what eve has ever deleted, so clearing it is not a
  // tidying-up gesture — it is throwing away the audit trail.
  const clear = async () => {
    if (!armed) {
      setArmed(true);
      setNote("This is the only record of what eve has deleted. Press again to clear it.");
      return;
    }
    setArmed(false);
    const n = await api.clearHistory().catch(() => 0);
    setNote(`Cleared ${n} entr${n === 1 ? "y" : "ies"}.`);
    await load();
  };

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setHeight(el.clientHeight));
    ro.observe(el);
    setHeight(el.clientHeight);
    return () => ro.disconnect();
  }, []);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter(
      (e) =>
        e.path.toLowerCase().includes(needle) ||
        e.category.toLowerCase().includes(needle),
    );
  }, [rows, q]);

  const reclaimed = useMemo(
    () => filtered.filter((e) => !e.dry_run && !e.error).reduce((s, e) => s + e.bytes, 0),
    [filtered],
  );

  // Only the rows on screen exist in the DOM.
  const first = Math.max(0, Math.floor(scrollTop / ROW) - 6);
  const count = Math.ceil(height / ROW) + 12;
  const slice = filtered.slice(first, first + count);

  return (
    <div className="scroll" style={{ display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div className="page-head">
        <h1>History</h1>
        <p>
          {total.toLocaleString()} entries · {bytes(reclaimed)} reclaimed
          {q && ` in ${filtered.length.toLocaleString()} matching`}
        </p>
      </div>

      <div className="toolbar">
        <div className="grow">
          <Search value={q} onChange={setQ} placeholder="Search by name, path or category…" />
        </div>
        <span className="rw-sub">{total} entries</span>
        <Btn kind={armed ? "danger" : "ghost"} size="sm" disabled={!total} onClick={clear}>
          {armed ? "Press again to clear" : "Clear history"}
        </Btn>
      </div>

      {note && <Card><p className="card-note">{note}</p></Card>}

      <Card>
        <div className="rw" style={{ gridTemplateColumns: "1fr 88px 150px", padding: "8px 16px" }}>
          <span className="rw-sub">Name and path</span>
          <span className="rw-sub" style={{ textAlign: "right" }}>Size</span>
          <span className="rw-sub" style={{ textAlign: "right" }}>When</span>
        </div>
        <div
          ref={box}
          onScroll={(e) => setScrollTop((e.target as HTMLDivElement).scrollTop)}
          style={{ height: "calc(100vh - 300px)", minHeight: 260, overflowY: "auto", margin: "0 -16px" }}
        >
          {!filtered.length && <Empty>{q ? "Nothing matches." : "eve has not deleted anything yet."}</Empty>}
          <div style={{ height: filtered.length * ROW, position: "relative" }}>
            {slice.map((e, i) => {
              const name = e.path.split("/").filter(Boolean).pop() ?? e.path;
              return (
                <div
                  key={`${e.at}-${first + i}-${e.path}`}
                  className="rw"
                  style={{
                    position: "absolute", top: (first + i) * ROW, left: 0, right: 0,
                    height: ROW, gridTemplateColumns: "1fr 88px 150px",
                  }}
                >
                  <div style={{ minWidth: 0 }}>
                    <div className="rw-name truncate">
                      {name}
                      {e.error ? " " : ""}
                      {e.error && <Pill tone="alert">failed</Pill>}
                      {e.dry_run && <Pill>preview</Pill>}
                    </div>
                    <div className="rw-sub truncate" title={e.path}>
                      {homeRelative(e.path)} · {e.category}
                    </div>
                  </div>
                  <div className="rw-size">{bytes(e.bytes)}</div>
                  <div className="rw-size">{when(e.at)}</div>
                </div>
              );
            })}
          </div>
        </div>
      </Card>
    </div>
  );
}
