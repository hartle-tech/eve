import { useCallback, useEffect, useRef, useState } from "react";
import { api, type BrowseResult, type DeleteOutcome } from "../tauri";
import { bytes, homeRelative } from "../format";
import { Btn, Card, Empty, Meter, Working } from "../ui";
import { ContextMenu, useContextMenu } from "../ContextMenu";

/// OmniDiskSweeper: one directory, biggest first, walk down, delete from here.
///
/// The old view ranked the home directory once and stopped. The thing that
/// makes OmniDiskSweeper useful is that "what is big" is a question you ask
/// again at every level — the answer at the top is almost never the file you
/// actually wanted to remove.
export function Disk({ onDeleted }: { onDeleted: () => void }) {
  const [res, setRes] = useState<BrowseResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState(false);
  const [typed, setTyped] = useState("");
  const [result, setResult] = useState<DeleteOutcome[] | null>(null);
  const [root, setRoot] = useState<string | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const menu = useContextMenu();
  const [locks, setLocks] = useState<string[]>([]);
  useEffect(() => { api.lockedPaths().then(setLocks).catch(() => {}); }, []);
  const isLocked = (p: string) => locks.some((l) => p === l || p.startsWith(l + "/"));
  const toggleLock = async (p: string) => {
    setLocks(await api.setLocked(p, !isLocked(p)).catch(() => locks));
  };

  // Only the newest navigation may write state.
  //
  // Listings take one to four seconds and vary wildly by directory, so two
  // clicks inside that window resolved in *filesystem* order rather than click
  // order — and the slower, earlier one landed last. Clicking Projects and then
  // Documents reliably ended up in Projects. That is the whole of "it jumps
  // back and forth from directory to directory".
  const nav = useRef(0);

  const go = useCallback(async (path: string | null) => {
    const ticket = ++nav.current;
    setBusy(true);
    setError(null);
    setPicked(new Set());
    setResult(null);
    // Move the breadcrumbs immediately. Until now the whole UI kept showing
    // the previous directory for the entire request, so a click looked
    // ignored, and the natural response — clicking again — is precisely what
    // triggered the race above.
    setPending(path);
    try {
      const r = await api.browse(path);
      if (ticket !== nav.current) return;
      setRes(r);
      setRoot((cur) => cur ?? r.path);
    } catch (e) {
      if (ticket !== nav.current) return;
      setError(String(e));
    } finally {
      if (ticket === nav.current) {
        setBusy(false);
        setPending(null);
      }
    }
  }, []);

  useEffect(() => { go(null); }, [go]);

  const toggle = (p: string) => {
    setPicked((s) => {
      const n = new Set(s);
      n.has(p) ? n.delete(p) : n.add(p);
      return n;
    });
  };

  const pickedBytes = (res?.entries ?? [])
    .filter((e) => picked.has(e.path))
    .reduce((s, e) => s + e.bytes, 0);

  const doDelete = async () => {
    setBusy(true);
    try {
      // A path picked before it was locked is still in the set. The policy
      // refuses it anyway, but sending it would put a refusal in the result
      // for something the user already told eve to leave alone.
      const outcomes = await api.deletePaths([...picked].filter((p) => !isLocked(p)));
      setConfirm(false);
      setTyped("");
      onDeleted();
      // Re-list *first*, then publish the result. `go` clears the result — it
      // has to, or a stale one would follow the user into the next folder —
      // and it was being called immediately after the result was set, which
      // wiped it every time. So a delete that worked and a delete that was
      // refused looked identical: nothing appeared at all. Half of "the disk
      // explorer delete does not work" was this, not the deletion.
      await go(res?.path ?? null);
      setResult(outcomes);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  // Everything is expressed *relative to the directory the user started in*.
  //
  // The bar used to be built from the absolute path, so it rendered
  // `Home / Users / vz` — and `/Users` was a live button that walked out of
  // the user's home. `↑ Up` had the same hole: `browse` documents that the
  // parent is `None` at the starting directory and never implemented it, so
  // Up climbed to /Users and then to /. That is "we click go up or reach root".
  const shownPath = pending ?? res?.path ?? "";
  const inRoot = root && shownPath.startsWith(root);
  const crumbs = (inRoot ? shownPath.slice(root!.length) : "").split("/").filter(Boolean);
  const atRoot = !root || shownPath === root;
  const parentWithinRoot =
    atRoot || crumbs.length === 0
      ? null
      : root + (crumbs.length > 1 ? "/" + crumbs.slice(0, -1).join("/") : "");
  const biggest = res?.entries[0]?.bytes || 1;
  const refused = result?.filter((r) => !r.ok) ?? [];
  const removed = result?.filter((r) => r.ok) ?? [];
  const freed = removed.reduce((s, r) => s + r.bytes, 0);

  return (
    <div className="scroll">
      <div className="page-head">
        <h1>Disk</h1>
        <p>
          Biggest first, at every level. Open a folder to see inside it.
          Lock one and nothing in it is ever removed — not by a cleanup, not by
          the unattended run, not by eve running as root.
        </p>
      </div>

      <div className="toolbar">
        <Btn size="sm" disabled={!parentWithinRoot}
             onClick={() => parentWithinRoot && go(parentWithinRoot)}>↑ Up</Btn>
        <div className="crumbs grow">
          <button className={`crumb${atRoot ? " is-last" : ""}`} onClick={() => go(null)}>Home</button>
          {crumbs.map((c, i) => {
            const p = root + "/" + crumbs.slice(0, i + 1).join("/");
            const last = i === crumbs.length - 1;
            return (
              <span key={p}>
                <span className="crumb-sep">/</span>
                <button className={`crumb${last ? " is-last" : ""}`} onClick={() => go(p)}>{c}</button>
              </span>
            );
          })}
        </div>
        {/* Sizes are remembered between visits, including the partial ones —
            that is what makes going Home instant instead of a two-second wait
            for the same numbers. This is how you ask for fresher ones. */}
        <Btn size="sm" disabled={busy || !res}
             onClick={async () => {
               if (!res) return;
               await api.refreshSizes(res.path);
               go(res.path);
             }}>Refresh</Btn>
        {picked.size > 0 && (
          <Btn kind="danger" size="sm" onClick={() => setConfirm(true)}>
            Delete {picked.size} · {bytes(pickedBytes)}
          </Btn>
        )}
      </div>

      {error && <Card><p className="card-note">{error}</p></Card>}

      {result && (
        <Card title="Result">
          <p className="card-note">
            {removed.length > 0
              ? `Removed ${removed.length} item${removed.length === 1 ? "" : "s"} · ${bytes(freed)}`
              : "Nothing was removed"}
            {refused.length > 0 &&
              ` · eve did not remove ${refused.length}, and here is why:`}
          </p>
          {/* The reason, not just the path. A list of paths under the word
              "refused" is what made this screen read as simply broken — the
              user could see that nothing happened and had no way to learn
              that, say, the folder was still in use. */}
          {refused.slice(0, 8).map((r) => (
            <div key={r.path} style={{ marginTop: 8 }}>
              <div className="rw-name truncate" title={r.path}>
                {homeRelative(r.path)}
              </div>
              <div className="rw-sub">{r.problem ?? "refused, with no reason given"}</div>
            </div>
          ))}
          {refused.length > 8 && (
            <p className="rw-sub">…and {refused.length - 8} more.</p>
          )}
        </Card>
      )}

      <Card
        title={shownPath ? homeRelative(shownPath) : "…"}
        sub={pending === null && res
          ? `${res.entries.length} items · ${bytes(res.total)}${res.complete ? "" : " (partial)"}`
          : undefined}
      >
        <div className="rows" style={{ margin: "0 -16px" }}>
          {/* While a navigation is in flight the rows still belong to the
              folder the user just left, so they are shown — losing your place
              for two seconds on every click is its own kind of broken — but
              made inert. Clicking a stale row is how you ask for a directory
              you are no longer in. */}
          {busy && !res && <Working label="Measuring this folder…" />}
          {pending === null && res && !res.entries.length && <Empty>This folder is empty.</Empty>}
          {res?.entries.map((e) => {
            const lockedHere = isLocked(e.path);
            // Locked by an ancestor rather than by this row. The lock still
            // applies, but the control here cannot lift it — offering a button
            // that appears to unlock and does not would be worse than none.
            const inherited = lockedHere && !locks.includes(e.path);
            return (
              <div key={e.path}
                   className={`rw rw-click${pending !== null ? " is-stale" : ""}${lockedHere ? " is-locked" : ""}`}
                   style={{ gridTemplateColumns: "18px 1fr 130px 92px 74px" }}
                   onContextMenu={menu.onContextMenu(e.path)}
                   onClick={() => (e.is_dir ? go(e.path) : toggle(e.path))}>
                <input type="checkbox" checked={picked.has(e.path)}
                       disabled={lockedHere}
                       onClick={(ev) => ev.stopPropagation()}
                       onChange={() => toggle(e.path)} />
                <div style={{ minWidth: 0 }}>
                  <div className="rw-name truncate">
                    {e.is_dir ? "📁 " : ""}{e.name}
                  </div>
                  <div className="rw-sub">
                    {e.is_dir ? `${e.children} inside` : "file"}
                    {!e.complete && " · partial"}
                    {lockedHere && (inherited
                      ? " · locked by a folder above it"
                      : " · locked — scans skip everything in here")}
                  </div>
                </div>
                <Meter fraction={e.bytes / biggest} />
                <div className="rw-size">{bytes(e.bytes)}</div>
                <div style={{ textAlign: "right" }} onClick={(ev) => ev.stopPropagation()}>
                  {e.is_dir && (
                    <Btn kind="bare" size="sm"
                         disabled={inherited}
                         onClick={() => toggleLock(e.path)}>
                      {lockedHere ? "🔒 Unlock" : "Lock"}
                    </Btn>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      <ContextMenu target={menu.target} onClose={menu.close} />

      {confirm && (
        <div className="modal-bg" onClick={() => setConfirm(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>Delete {picked.size} item{picked.size === 1 ? "" : "s"}?</h2>
            <p>
              {bytes(pickedBytes)}. These go to the Trash, and eve still refuses
              anything protected, in use, or on your whitelist — you will see
              what it declined.
            </p>
            <p>Type <b>delete</b> to confirm.</p>
            <input className="input" autoFocus value={typed} placeholder="delete"
                   style={{ width: "100%", marginTop: 8 }}
                   onChange={(e) => setTyped(e.target.value)} />
            <div className="modal-actions">
              <Btn onClick={() => { setConfirm(false); setTyped(""); }}>Cancel</Btn>
              <Btn kind="danger" disabled={typed.trim().toLowerCase() !== "delete"}
                   onClick={doDelete}>Delete</Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
