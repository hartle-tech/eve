import { useEffect, useMemo, useState } from "react";
import { api, type DeleteOutcome, type Machine, type MachineKind } from "../tauri";
import { bytes, homeRelative } from "../format";
import { Btn, Card, Empty, Meter, Pill, Skeleton, Working } from "../ui";
import { ContextMenu, useContextMenu } from "../ContextMenu";

/// Containers, virtual machines and emulators.
///
/// The largest things on a developer's disk that no cache cleaner looks at,
/// because they are not caches: a container image store or a VM disk is state
/// somebody chose to create. So this screen reports rather than recommends —
/// sizes, what removing each one costs, and the tool's own command where that
/// is a better idea than deleting the directory.
const ORDER: { kind: MachineKind; title: string; note: string }[] = [
  {
    kind: "containers",
    title: "Container storage",
    note: "Images, layers and volumes. Images re-pull; volume data does not come back.",
  },
  {
    kind: "virtual-machine",
    title: "Virtual machines",
    note: "Whole machines and everything inside them. Nothing here is a cache.",
  },
  {
    kind: "emulator",
    title: "Emulators and simulators",
    note: "Simulated devices and whatever is installed on them.",
  },
];

export function Machines() {
  const menu = useContextMenu();
  const [machines, setMachines] = useState<Machine[] | null>(null);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState(false);
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<DeleteOutcome[] | null>(null);

  const load = () => {
    setBusy(true);
    api.listMachines()
      .then(setMachines)
      .catch(() => setMachines([]))
      .finally(() => setBusy(false));
  };
  useEffect(load, []);

  const total = (machines ?? []).reduce((s, m) => s + m.bytes, 0);
  const pickedBytes = (machines ?? [])
    .filter((m) => picked.has(m.path))
    .reduce((s, m) => s + m.bytes, 0);
  const biggest = machines?.[0]?.bytes || 1;

  const sections = useMemo(
    () =>
      ORDER.map((o) => ({ ...o, items: (machines ?? []).filter((m) => m.kind === o.kind) }))
        .filter((s) => s.items.length > 0),
    [machines],
  );

  const toggle = (p: string) =>
    setPicked((s) => { const n = new Set(s); n.has(p) ? n.delete(p) : n.add(p); return n; });

  const remove = async () => {
    setBusy(true);
    try {
      const out = await api.removeMachines([...picked], true);
      setConfirm(false);
      setTyped("");
      setPicked(new Set());
      setResult(out);
      load();
    } finally {
      setBusy(false);
    }
  };

  // The tool's own command, where one exists, for everything selected. Deleting
  // a container store by hand leaves the engine believing its images are still
  // there, so this is the better answer and worth putting in front of the
  // destructive button rather than after it.
  const commands = (machines ?? [])
    .filter((m) => picked.has(m.path) && m.better_command)
    .map((m) => m.better_command!);

  return (
    <div className="scroll">
      <div className="page-head">
        <h1>Machines</h1>
        <p>
          Containers, virtual machines and emulators. Not caches — eve never
          touches these on its own, and never at all unattended.
        </p>
      </div>

      <div className="toolbar">
        <span className="rw-sub">
          {machines === null ? "Measuring…" : `${bytes(total)} across ${machines.length} store${machines.length === 1 ? "" : "s"}`}
        </span>
        {busy && machines !== null && <Working label="Measuring…" inline />}
        <span className="grow" />
        {picked.size > 0 && (
          <>
            <span className="rw-sub">{picked.size} selected · {bytes(pickedBytes)}</span>
            <Btn kind="ghost" size="sm" onClick={() => setPicked(new Set())}>Clear</Btn>
            <Btn kind="danger" size="sm" disabled={busy} onClick={() => setConfirm(true)}>
              Remove {bytes(pickedBytes)}
            </Btn>
          </>
        )}
      </div>

      {result && (
        <Card title={result.some((r) => r.ok) ? "Removed" : "Nothing was removed"}>
          <p className="card-note">
            {bytes(result.filter((r) => r.ok).reduce((s, r) => s + r.bytes, 0))} moved to the Trash.
          </p>
          {result.filter((r) => !r.ok).map((r) => (
            <p key={r.path} className="rw-sub">{r.problem}</p>
          ))}
        </Card>
      )}

      {machines === null && <Card sub="Looking for containers and VMs…"><Skeleton rows={4} /></Card>}
      {machines?.length === 0 && (
        <Card><Empty>No container or VM storage on this Mac.</Empty></Card>
      )}

      {sections.map((s) => (
        <div key={s.kind} style={{ marginTop: 12 }}>
          <Card
            title={s.title}
            sub={`${bytes(s.items.reduce((n, m) => n + m.bytes, 0))}`}
          >
            <p className="card-note">{s.note}</p>
            <div className="rows" style={{ margin: "0 -16px" }}>
              {s.items.map((m) => (
                <div key={m.path} className="rw rw-click"
                     style={{ gridTemplateColumns: "18px 1fr 150px 100px" }}
                     onContextMenu={menu.onContextMenu(m.path)}
                     onClick={() => toggle(m.path)}>
                  <input type="checkbox" checked={picked.has(m.path)}
                         onClick={(e) => e.stopPropagation()}
                         onChange={() => toggle(m.path)} />
                  <div style={{ minWidth: 0 }}>
                    <div className="rw-name truncate">
                      {m.name}
                      {!m.complete && <Pill tone="warn">partial</Pill>}
                    </div>
                    <div className="rw-sub truncate" title={m.path}>
                      {homeRelative(m.path)}
                    </div>
                    <div className="rw-sub">{m.cost}</div>
                  </div>
                  <Meter fraction={m.bytes / biggest} />
                  <div className="rw-size">{bytes(m.bytes)}</div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      ))}

      <ContextMenu target={menu.target} onClose={menu.close} />

      {confirm && (
        <div className="modal-bg" onClick={() => setConfirm(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h2>Remove {picked.size} store{picked.size === 1 ? "" : "s"}?</h2>
            <p>
              {bytes(pickedBytes)}, moved to the Trash. These are not caches:
              anything running inside them goes too.
            </p>
            {commands.length > 0 && (
              <p className="card-note">
                Each tool can do this better than deleting the folder — it keeps
                the tool's own bookkeeping straight:
                {commands.map((c) => <code key={c} style={{ display: "block", marginTop: 4 }}>{c}</code>)}
              </p>
            )}
            <p>Type <b>remove</b> to confirm.</p>
            <input className="input" autoFocus value={typed} placeholder="remove"
                   style={{ width: "100%", marginTop: 8 }}
                   onChange={(e) => setTyped(e.target.value)} />
            {busy && <Working label="Removing…" inline />}
            <div className="modal-actions">
              <Btn onClick={() => { setConfirm(false); setTyped(""); }}>Cancel</Btn>
              <Btn kind="danger" disabled={busy || typed.trim().toLowerCase() !== "remove"}
                   onClick={remove}>Remove</Btn>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
