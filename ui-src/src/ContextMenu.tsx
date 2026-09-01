import { useCallback, useEffect, useRef, useState } from "react";
import { api, type Holder } from "./tauri";

/// Right-click anything that has a path.
///
/// Every list in eve is a list of paths, and until now none of them could be
/// acted on outside eve's own verbs — you could see that a folder was 40 GB, or
/// that something was holding it open, and had no way to go and look. The two
/// questions people actually have at that moment are "where is this?" and, when
/// eve refused because the owner is live, "what is holding it?".
///
/// One hook, one menu, wired wherever a row has a path.

/// Either a place on disk, or a running process.
///
/// A process is not a path — you cannot reveal a pid — but the two questions
/// people ask are the same shape: *where is this* and *make it stop*. One menu
/// answers both, and the row decides which it is.
export type MenuTarget =
  | { kind: "path"; path: string; x: number; y: number }
  | { kind: "process"; pid: number; name: string; exe: string | null; x: number; y: number }
  | null;

export function useContextMenu() {
  const [target, setTarget] = useState<MenuTarget>(null);

  const onContextMenu = useCallback(
    (path: string) => (e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setTarget({ kind: "path", path, x: e.clientX, y: e.clientY });
    },
    [],
  );

  const onProcessMenu = useCallback(
    (pid: number, name: string, exe: string | null) => (e: React.MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      setTarget({ kind: "process", pid, name, exe, x: e.clientX, y: e.clientY });
    },
    [],
  );

  const close = useCallback(() => setTarget(null), []);
  return { target, onContextMenu, onProcessMenu, close };
}

export function ContextMenu({ target, onClose }: { target: MenuTarget; onClose: () => void }) {
  const [holders, setHolders] = useState<Holder[] | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  // Who is holding it is looked up as the menu opens, not on hover: `lsof`
  // takes a moment, and a menu item that appears late is a menu item people
  // click through by accident.
  useEffect(() => {
    setHolders(null);
    setNote(null);
    if (!target) return;
    if (target.kind !== "path") { setHolders([]); return; }
    let live = true;
    api.owningProcesses(target.path)
      .then((h) => { if (live) setHolders(h); })
      .catch(() => { if (live) setHolders([]); });
    return () => { live = false; };
  }, [target]);

  useEffect(() => {
    if (!target) return;
    const away = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", esc);
    };
  }, [target, onClose]);

  if (!target) return null;

  const run = async (f: () => Promise<unknown>, ok: string) => {
    try {
      await f();
      setNote(ok);
      setTimeout(onClose, 400);
    } catch (e) {
      setNote(String(e));
    }
  };

  // Keep the menu on screen when the row is near the bottom or the right edge.
  const style: React.CSSProperties = {
    position: "fixed",
    left: Math.min(target.x, window.innerWidth - 250),
    top: Math.min(target.y, window.innerHeight - 220),
    zIndex: 200,
  };

  // A process's "where" is its executable, which is a path like any other —
  // so the same two actions work once it is resolved.
  const where = target.kind === "path" ? target.path : target.exe;
  const heading =
    target.kind === "path"
      ? target.path.split("/").filter(Boolean).pop() ?? target.path
      : `${target.name} (${target.pid})`;

  return (
    <div className="ctx" style={style} ref={ref} onClick={(e) => e.stopPropagation()}>
      <div className="ctx-head truncate" title={where ?? heading}>{heading}</div>

      {where ? (
        <>
          <button className="ctx-item" onClick={() => run(() => api.revealInFinder(where), "Revealed")}>
            Reveal in Finder
          </button>
          <button className="ctx-item" onClick={() => run(() => api.revealInTerminal(where), "Opened")}>
            Reveal in Terminal
          </button>
        </>
      ) : (
        <div className="ctx-note">macOS will not say where this one lives.</div>
      )}

      {target.kind === "process" && (
        <>
          <div className="ctx-sep" />
          <button className="ctx-item ctx-danger"
                  onClick={() => run(() => api.killProcess(target.pid), `Asked ${target.name} to quit`)}>
            Quit {target.name}
          </button>
        </>
      )}

      {target.kind === "path" && holders === null && (
        <div className="ctx-note">Looking for what has this open…</div>
      )}
      {target.kind === "path" && holders !== null && holders.length > 0 && (
        <>
          <div className="ctx-sep" />
          <div className="ctx-note">
            {holders.length === 1 ? "1 process has this open" : `${holders.length} processes have this open`}
          </div>
          {holders.slice(0, 5).map((h) => (
            <button key={h.pid} className="ctx-item ctx-danger"
                    onClick={() => run(() => api.killProcess(h.pid), `Asked ${h.name} to quit`)}>
              Quit {h.name} <span className="ctx-dim">({h.pid})</span>
            </button>
          ))}
        </>
      )}
      {note && <div className="ctx-note">{note}</div>}
    </div>
  );
}
