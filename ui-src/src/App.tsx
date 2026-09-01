import { useCallback, useEffect, useRef, useState } from "react";
import { api, type CleanReport, type PermissionStatus, type Preferences, type Status } from "./tauri";
import { bytes } from "./format";
import { Onboarding } from "./Onboarding";
import { Dashboard } from "./screens/Dashboard";
import { Clean } from "./screens/Clean";
import { Disk } from "./screens/Disk";
import { Apps } from "./screens/Apps";
import { Machines } from "./screens/Machines";
import { History } from "./screens/History";
import { Health } from "./screens/Health";
import { Settings } from "./screens/Settings";

type View = "home" | "clean" | "disk" | "apps" | "machines" | "history" | "health" | "settings";

const NAV: { id: View; label: string; icon: JSX.Element }[] = [
  { id: "home", label: "Overview", icon: <><rect x="2.5" y="2.5" width="5" height="5" rx="1.2" /><rect x="8.5" y="2.5" width="5" height="5" rx="1.2" /><rect x="2.5" y="8.5" width="5" height="5" rx="1.2" /><rect x="8.5" y="8.5" width="5" height="5" rx="1.2" /></> },
  { id: "clean", label: "Clean", icon: <><path d="M3 4h10M3 8h10M3 12h6" /></> },
  { id: "disk", label: "Disk", icon: <><circle cx="8" cy="8" r="5.5" /><circle cx="8" cy="8" r="1.5" /></> },
  { id: "apps", label: "Applications", icon: <><rect x="2.5" y="2.5" width="11" height="11" rx="2.5" /><path d="M6 8h4" /></> },
  { id: "machines", label: "Machines", icon: <><rect x="1.5" y="3.5" width="13" height="8" rx="1.5" /><path d="M5 13.5h6" /></> },
  { id: "history", label: "History", icon: <><circle cx="8" cy="8" r="5.5" /><path d="M8 5v3.2l2 1.3" /></> },
  { id: "health", label: "Health", icon: <><path d="M2 8.5h3l1.5-4 3 8L11 8.5h3" /></> },
  { id: "settings", label: "Settings", icon: <><circle cx="8" cy="8" r="2.2" /><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.4 3.4l1.4 1.4M11.2 11.2l1.4 1.4M12.6 3.4l-1.4 1.4M4.8 11.2l-1.4 1.4" /></> },
];

const SKIP_KEY = "eve.onboarding.skipped";

export default function App() {
  // The hash picks the opening view. Harmless in the app — nothing links to
  // one — and it is what lets every screen be rendered and checked headlessly
  // without rebuilding the .app for each one.
  const [view, setView] = useState<View>(
    () => (NAV.some((n) => n.id === location.hash.slice(1))
      ? (location.hash.slice(1) as View)
      : "home"),
  );
  const [report, setReport] = useState<CleanReport | null>(null);
  const [status, setStatus] = useState<Status | null>(null);
  const [prefs, setPrefs] = useState<Preferences | null>(null);
  const [perms, setPerms] = useState<PermissionStatus[]>([]);
  const [busy, setBusy] = useState(false);
  const [armed, setArmed] = useState(false);
  const [note, setNote] = useState("Looking through your caches, logs and scratch space…");
  const [skipped, setSkipped] = useState(false);
  const [wasBlocked, setWasBlocked] = useState(false);
  const [restarting, setRestarting] = useState(false);
  const [freedLast, setFreedLast] = useState<number | null>(null);

  // A scan is single-flight and generation-tracked: a walk that started before
  // a settings change must not come back and declare its stale result current.
  const inFlight = useRef<Promise<CleanReport | null> | null>(null);
  const generation = useRef(0);
  const scanned = useRef(-1);

  const scan = useCallback(async (force = false) => {
    if (!force && report && scanned.current === generation.current) return report;
    if (inFlight.current) return inFlight.current;
    const startedAt = generation.current;
    setBusy(true);
    inFlight.current = (async () => {
      try {
        const r = await api.scan(false);
        scanned.current = startedAt;
        setReport(r);
        return r;
      } catch {
        setNote("eve could not read the disk. Check its permissions in Settings.");
        return null;
      } finally {
        setBusy(false);
        inFlight.current = null;
      }
    })();
    return inFlight.current;
  }, [report]);

  const loadPerms = useCallback(async (recheck = false) => {
    try {
      const p = recheck ? await api.recheckPermissions() : await api.permissions();
      setPerms(p);
      return p;
    } catch { return []; }
  }, []);

  useEffect(() => {
    try { setSkipped(localStorage.getItem(SKIP_KEY) === "1"); } catch { /* private window */ }
    api.preferences().then(setPrefs).catch(() => {});
    api.status().then(setStatus).catch(() => {});
    loadPerms().then(() => scan());
    const id = setInterval(() => api.status().then(setStatus).catch(() => {}), 5000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const blocking = perms.filter((p) => p.required && p.state === "denied");
  useEffect(() => { if (blocking.length) setWasBlocked(true); }, [blocking.length]);

  // Coming back from System Settings is the only signal macOS gives that an
  // answer changed. If the last blocker just cleared, eve restarts — a
  // permission granted a second ago is not in effect in this process.
  useEffect(() => {
    const onFocus = async () => {
      if (!perms.length) return;
      const before = perms.some((p) => p.required && p.state === "denied");
      const now = await loadPerms(true);
      const after = now.some((p) => p.required && p.state === "denied");
      if (before && !after) restart();
    };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [perms, loadPerms]);

  const restart = async () => {
    setRestarting(true);
    try { await api.relaunch(); }
    catch { setRestarting(false); setWasBlocked(false); scan(true); }
  };

  const clean = async () => {
    if (!armed) {
      setArmed(true);
      setNote("Press again to confirm. Nothing has been deleted yet.");
      return;
    }
    setArmed(false);
    setBusy(true);
    setNote("Cleaning…");
    try {
      const r = await api.clean(false);
      const direct = !!(prefs?.["permanent-delete"] || prefs?.["empty-trash"]);
      const freed = r.categories.reduce(
        (s, c) => s + c.reports.reduce((a, x) => a + (x.outcome?.bytes ?? 0), 0), 0);

      // Re-scan, and do **not** show the clean report as if it were a scan.
      //
      // A clean report's byte counts are what was just *deleted*. Rendering it
      // in the "ready to reclaim" position meant the figure did not move after
      // a successful cleanup — so it looked like nothing had happened, and the
      // obvious response was to run it again. That is the whole of "I have to
      // scan and run the cleanup twice".
      //
      // What belongs there afterwards is what is left, which only a fresh scan
      // knows. The amount freed goes in the note, where it is a result rather
      // than a forecast.
      generation.current += 1;
      setFreedLast(freed);
      await scan(true);
      api.status().then(setStatus).catch(() => {});

      // eve adds an exclusion by itself when a Trash entry turns out to be
      // permanently undeletable. Saying so is the difference between a rule
      // the user can go and change and one that appeared out of nowhere.
      const learned = r.newly_excluded?.length
        ? ` ${r.newly_excluded.length} Trash item${r.newly_excluded.length === 1 ? "" : "s"} \
turned out to be permanently undeletable (${r.newly_excluded.join(", ")}); eve now skips \
${r.newly_excluded.length === 1 ? "it" : "them"} — see Settings to change that.`
        : "";
      setNote((direct
        ? `Reclaimed ${bytes(freed)}. The space is free now, and none of it can be recovered.`
        : `Moved ${bytes(freed)} to the Trash — recoverable, but not free until you empty it. Settings can make that automatic.`)
        + learned);
    } catch (e) {
      setNote(`Cleanup failed: ${e}`);
    } finally {
      setBusy(false);
    }
  };

  const fda = perms.find((p) => p.permission === "full-disk-access");
  const fdaMissing = fda?.state === "denied";
  const showOnboarding = !skipped && (blocking.length > 0 || (wasBlocked && !restarting));

  if (showOnboarding) {
    return (
      <Onboarding
        perms={perms} blocking={blocking} restarting={restarting}
        onContinue={restart}
        onSkip={() => {
          setSkipped(true);
          try { localStorage.setItem(SKIP_KEY, "1"); } catch { /* private window */ }
          scan();
        }}
      />
    );
  }

  return (
    <div className="shell">
      {/* The window has no title bar (`titleBarStyle: Overlay`, `hiddenTitle`),
          which also means it has nothing to drag it by. Tauri needs the region
          declared explicitly — `-webkit-app-region: drag` does nothing here.
          The strip runs the full width behind the traffic lights, so the whole
          top edge works the way every other Mac window does. */}
      <div
        className="titlebar"
        data-tauri-drag-region
        onMouseDown={(e) => {
          // Both, because the attribute alone did not move the window here.
          // `data-tauri-drag-region` is handled inside the webview and is easy
          // to lose to an overlapping element or a swallowed mousedown;
          // `startDragging()` asks the window itself and cannot be intercepted.
          // Left button only, and never on a double-click — that is zoom.
          if (e.button !== 0 || e.detail > 1) return;
          const w = (window as any).__TAURI__?.window;
          try { w?.getCurrentWindow?.().startDragging?.(); } catch { /* not in Tauri */ }
        }}
        onDoubleClick={() => {
          // What every Mac title bar does: zoom.
          const w = (window as any).__TAURI__?.window;
          try { w?.getCurrentWindow?.().toggleMaximize?.(); } catch { /* not in Tauri */ }
        }}
      />

      <aside className="rail">
        <div className="rail-brand" data-tauri-drag-region>
          <span className="rail-mark" /> eve
        </div>
        {NAV.map((n) => (
          <button key={n.id} className={`nav${view === n.id ? " is-active" : ""}`}
                  onClick={() => { setView(n.id); if (n.id === "clean" || n.id === "home") scan(); }}>
            <svg viewBox="0 0 16 16">{n.icon}</svg>
            <span>{n.label}</span>
            {n.id === "settings" && fdaMissing && <span className="nav-badge">▲</span>}
          </button>
        ))}
        <div className="rail-foot">
          <div className="stat-label">Free</div>
          <div style={{ fontSize: 17, fontWeight: 650, letterSpacing: "-0.02em" }}>
            {bytes(report?.free_after ?? status?.volumes?.[0]?.available ?? 0)}
          </div>
        </div>
      </aside>

      <main className="content">
        {view === "home" && (
          <Dashboard report={report} status={status} busy={busy} freedLast={freedLast}
                     onClean={() => { setView("clean"); clean(); }}
                     onGo={(v) => setView(v as View)} />
        )}
        {view === "clean" && (
          <Clean report={report} busy={busy} armed={armed} note={note}
                 fdaMissing={fdaMissing} onFixFda={() => api.openPrivacySettings("full-disk-access")}
                 onScan={() => scan(true)} onClean={clean} />
        )}
        {view === "disk" && <Disk onDeleted={() => { generation.current += 1; }} />}
        {view === "apps" && <Apps />}
        {view === "machines" && <Machines />}
        {view === "history" && <History />}
        {view === "health" && <Health />}
        {view === "settings" && (
          <Settings perms={perms} onRefreshPerms={() => loadPerms(true)} />
        )}
      </main>
    </div>
  );
}
