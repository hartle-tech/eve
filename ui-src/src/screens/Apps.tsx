import { useEffect, useMemo, useState } from "react";
import { api, type AppInfo, type AppKind, type UninstallBatch } from "../tauri";
import { bytes, homeRelative } from "../format";
import { Btn, Card, Empty, Pill, Search, Skeleton, Working } from "../ui";
import { ContextMenu, useContextMenu } from "../ContextMenu";

/// Select several, see one combined preview, remove them together.
///
/// Removing an app is `Destructive` tier, which is the one tier the safety
/// core says needs a typed confirmation. The window had never honoured that —
/// it armed a button twice like everything else. A batch of app removals is
/// exactly where that shortcut stops being acceptable, so the typed confirm
/// lives here.
export function Apps() {
  const menu = useContextMenu();
  const [apps, setApps] = useState<AppInfo[]>([]);
  const [q, setQ] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [preview, setPreview] = useState<UninstallBatch | null>(null);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(true);
  const [done, setDone] = useState<UninstallBatch | null>(null);
  const [showSystem, setShowSystem] = useState(false);

  const load = () => {
    setBusy(true);
    api.listApps().then((a) => setApps(a)).catch(() => {}).finally(() => setBusy(false));
  };
  useEffect(load, []);

  const shown = useMemo(() => {
    const n = q.trim().toLowerCase();
    const list = n ? apps.filter((a) => a.name.toLowerCase().includes(n)) : apps;
    return [...list].sort((a, b) => b.bytes - a.bytes);
  }, [apps, q]);

  /// Grouped, biggest group first, with the un-removable one always last.
  ///
  /// A flat alphabetical list made the user do the sorting: Xcode and a
  /// menu-bar toy looked identical, and the things nobody can remove were
  /// mixed in with the things they can.
  const sections = useMemo(() => {
    const order: { kind: AppKind; title: string }[] = [
      { kind: "development", title: "Development" },
      { kind: "user", title: "Installed by you" },
      { kind: "apple-extra", title: "Apple extras" },
      { kind: "mac-os", title: "Part of macOS" },
    ];
    return order
      .map(({ kind, title }) => {
        const list = shown.filter((a) => a.kind === kind);
        const removables = list.filter((a) => a.removable);
        return {
          kind, title, apps: list,
          removable: removables.length > 0,
          allPicked: removables.length > 0 && removables.every((a) => picked.has(a.path)),
        };
      })
      .filter((s) => s.apps.length > 0);
  }, [shown, picked]);

  const selectAll = (list: AppInfo[], on: boolean) =>
    setPicked((s) => {
      const n = new Set(s);
      // Only ever ticks what can actually be removed, so "select all" can
      // never arm a row that has no checkbox.
      list.filter((a) => a.removable).forEach((a) => (on ? n.add(a.path) : n.delete(a.path)));
      return n;
    });

  const loadSystem = () => {
    setShowSystem(true);
    setBusy(true);
    api.listApps(true).then(setApps).catch(() => {}).finally(() => setBusy(false));
  };

  const pickedBytes = apps.filter((a) => picked.has(a.path)).reduce((s, a) => s + a.bytes, 0);

  const toggle = (p: string) =>
    setPicked((s) => { const n = new Set(s); n.has(p) ? n.delete(p) : n.add(p); return n; });

  const doPreview = async () => {
    setBusy(true);
    try { setPreview(await api.uninstallApps([...picked], false)); }
    finally { setBusy(false); }
  };

  const doRemove = async (privileged = false) => {
    setBusy(true);
    try {
      const r = await api.uninstallApps([...picked], true, privileged);
      setDone(r); setPreview(null); setTyped(""); setPicked(new Set());
      load();
    } finally { setBusy(false); }
  };

  const refused = preview?.reports.filter((r) => r.denial) ?? [];
  const needsAdmin = preview?.apps.filter((a) => a.needs_admin) ?? [];

  return (
    <div className="scroll">
      <div className="page-head">
        <h1>Applications</h1>
        <p>Remove apps and everything they left behind. Several at a time.</p>
      </div>

      <div className="toolbar">
        <div className="grow"><Search value={q} onChange={setQ} placeholder="Search applications…" /></div>
        {picked.size > 0 && (
          <>
            <span className="rw-sub">{picked.size} selected · {bytes(pickedBytes)}</span>
            <Btn kind="ghost" size="sm" onClick={() => setPicked(new Set())}>Clear</Btn>
            <Btn kind="danger" size="sm" disabled={busy} onClick={doPreview}>Review removal</Btn>
          </>
        )}
      </div>

      {done && (
        <Card title={done.freed_bytes > 0 ? "Removed" : "Nothing was removed"}>
          {/* `freed_bytes`, never `total_bytes`. The plan's total is a
              forecast; showing it here is what let the window report the full
              size of an application that was still sitting in the Dock. */}
          <p className="card-note">
            {done.freed_bytes > 0
              ? `${done.apps.length} application${done.apps.length === 1 ? "" : "s"} · ${bytes(done.freed_bytes)} freed.`
              : "eve could not remove any of these."}
          </p>
          {done.problems.slice(0, 6).map((p, i) => (
            <p key={i} className="rw-sub">{p}</p>
          ))}
          {done.problems.length > 6 && (
            <p className="rw-sub">…and {done.problems.length - 6} more.</p>
          )}
        </Card>
      )}

      {busy && !apps.length && <Card sub="Looking through /Applications…"><Skeleton rows={5} /></Card>}
      {!busy && !shown.length && <Card><Empty>Nothing matches.</Empty></Card>}

      {sections.map((s) => (
        <div key={s.kind} style={{ marginTop: 12 }}>
          <Card
            title={s.title}
            sub={`${s.apps.length} · ${bytes(s.apps.reduce((n, a) => n + a.bytes, 0))}`}
            action={
              s.removable ? (
                <Btn kind="bare" size="sm" onClick={() => selectAll(s.apps, !s.allPicked)}>
                  {s.allPicked ? "Clear all" : "Select all"}
                </Btn>
              ) : (
                <span className="rw-sub">Part of macOS — cannot be removed</span>
              )
            }
          >
            {s.kind === "mac-os" && (
              <p className="card-note">
                These live on the sealed system volume. Nothing can remove them —
                not eve, not an administrator. Listed so you can see what they cost.
              </p>
            )}
            <div className="rows" style={{ margin: "0 -16px" }}>
              {s.apps.map((a) => (
                <div key={a.path}
                     className={`rw${a.removable ? " rw-click" : ""}`}
                     style={{ gridTemplateColumns: "18px 1fr 110px" }}
                     onContextMenu={menu.onContextMenu(a.path)}
                     onClick={() => a.removable && toggle(a.path)}>
                  {a.removable ? (
                    <input type="checkbox" checked={picked.has(a.path)}
                           onClick={(e) => e.stopPropagation()} onChange={() => toggle(a.path)} />
                  ) : (
                    <span className="rw-sub" title="Part of macOS">🔒</span>
                  )}
                  <div style={{ minWidth: 0 }}>
                    <div className="rw-name truncate">
                      {a.name}
                      {a.needs_admin && <Pill tone="warn">needs admin</Pill>}
                    </div>
                    <div className="rw-sub truncate">{a.bundle_id ?? homeRelative(a.path)}</div>
                  </div>
                  <div className="rw-size">{bytes(a.bytes)}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      ))}

      {!showSystem && (
        <div style={{ marginTop: 12 }}>
          <Btn kind="ghost" size="sm" onClick={loadSystem} disabled={busy}>
            Also show what macOS ships
          </Btn>
        </div>
      )}

      {preview && (
        <div className="modal-bg" onClick={() => setPreview(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>Remove {preview.apps.length} application{preview.apps.length === 1 ? "" : "s"}?</h2>
            <p>{bytes(preview.total_bytes)} across {preview.reports.length} items.</p>
            <div style={{ maxHeight: 180, overflowY: "auto", margin: "10px 0" }}>
              {preview.apps.map((a) => (
                <div key={a.path} className="rw" style={{ padding: "5px 0", gridTemplateColumns: "1fr auto" }}>
                  <span className="truncate">{a.name}</span>
                  <span className="rw-size">{bytes(a.bytes)} · {a.items}</span>
                </div>
              ))}
            </div>
            {refused.length > 0 && (
              <p className="card-note">eve will refuse {refused.length} of these — shared or protected files.</p>
            )}
            {/* Said before they commit, not after it looks like a failure.
                These bundles are root-owned, and POSIX will not let this user
                move a directory they cannot write into a different parent —
                no switch in System Settings changes that. */}
            {needsAdmin.length > 0 && (
              <p className="card-note">
                The system owns {needsAdmin.map((a) => a.name).join(", ")} — installed by a
                package, not dragged in. Removing {needsAdmin.length === 1 ? "it" : "them"} needs
                administrator rights, and macOS will ask you for your password.
              </p>
            )}
            <p>
              This is the one thing eve asks you to type. Enter <b>remove</b> to confirm.
            </p>
            <input className="input" autoFocus value={typed} placeholder="remove"
                   style={{ width: "100%", marginTop: 8 }}
                   onChange={(e) => setTyped(e.target.value)} />
            {busy && <Working label="Removing…" inline />}
            <div className="modal-actions">
              <Btn onClick={() => { setPreview(null); setTyped(""); }}>Cancel</Btn>
              <Btn kind="danger" disabled={busy || typed.trim().toLowerCase() !== "remove"}
                   onClick={() => doRemove(needsAdmin.length > 0)}>
                {needsAdmin.length > 0 ? "Remove as administrator" : "Remove"}
              </Btn>
            </div>
          </div>
        </div>
      )}

      <ContextMenu target={menu.target} onClose={menu.close} />
    </div>
  );
}
