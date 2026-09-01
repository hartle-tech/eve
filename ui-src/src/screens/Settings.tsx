import { useEffect, useState } from "react";
import { api, type AgentStatus, type CategoryInfo, type PermissionStatus, type Preferences } from "../tauri";
import { duration, fuzzyScore } from "../format";
import { Btn, Card, Empty, Pill, Search, Section, Switch, Warn } from "../ui";

/// Presets, not seconds.
///
/// The old control was a number field containing 10800 and no hint of what a
/// reasonable value looked like. Nobody knows 10800 is three hours; everybody
/// knows "every 3 hours". The stored value is still seconds, so the engine,
/// the CLI and the LaunchAgent are untouched — this is purely about what the
/// user is asked to think in.
const CADENCE = [
  { label: "Hourly", secs: 3600 },
  { label: "3 hours", secs: 10800 },
  { label: "6 hours", secs: 21600 },
  { label: "Daily", secs: 86400 },
];

const THRESHOLDS = [2, 5, 10, 15, 20, 30, 50];

export function Settings({ perms, onRefreshPerms }: {
  perms: PermissionStatus[];
  onRefreshPerms: () => void;
}) {
  const [p, setP] = useState<Preferences | null>(null);
  // The deep probe costs a permission dialog, so it runs when the user opens
  // the screen that shows permissions — not on every launch, which is what
  // made eve ask on startup for ever.
  useEffect(() => { onRefreshPerms(); }, []);

  const [exclusions, setExclusions] = useState<[string, string][]>([]);
  const [agent, setAgent] = useState<AgentStatus | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [adding, setAdding] = useState("");
  const [cats, setCats] = useState<CategoryInfo[]>([]);
  const [q, setQ] = useState("");
  useEffect(() => { api.categories().then(setCats).catch(() => {}); }, []);

  // Ranked, so the closest match is first rather than merely the earliest in
  // catalog order — which is what makes a search feel like Apple's rather than
  // like a filter.
  const shownCats = q.trim()
    ? cats
        .map((c) => ({ c, s: Math.max(
            fuzzyScore(q, c.title) ?? -Infinity,
            (fuzzyScore(q, c.group) ?? -Infinity) - 2,
            (fuzzyScore(q, c.description) ?? -Infinity) - 6,
            (fuzzyScore(q, c.key) ?? -Infinity) - 1,
          ) }))
        .filter((x) => x.s > -Infinity)
        .sort((a, b) => b.s - a.s)
        .map((x) => x.c)
    : cats;

  const matches = (...fields: string[]) =>
    !q.trim() || fields.some((f) => fuzzyScore(q, f) !== null);

  const toggleCat = async (key: string, on: boolean) => {
    setCats((cs) => cs.map((c) => (c.key === key ? { ...c, enabled: on } : c)));
    try { setP(await api.setCategoryEnabled(key, on)); }
    catch (e) { setErr(String(e)); }
  };

  const load = async () => {
    try {
      setP(await api.preferences());
      setExclusions(await api.trashExclusions());
    } catch (e) { setErr(String(e)); }
    api.agentStatus().then(setAgent).catch(() => {});
  };
  useEffect(() => { load(); }, []);

  const save = async (next: Partial<{
    directCleanup: boolean; thresholdGb: number; cooldownSec: number; trashExclusions: string[];
  }>) => {
    if (!p) return;
    setErr(null);
    const body = {
      directCleanup: next.directCleanup ?? !!(p["permanent-delete"] || p["empty-trash"]),
      thresholdGb: next.thresholdGb ?? p["threshold-gb"],
      cooldownSec: next.cooldownSec ?? p["cooldown-sec"],
      trashExclusions: next.trashExclusions ?? p["trash-exclusions"],
    };
    try { setP(await api.setPreferences(body)); }
    catch (e) { setErr(String(e)); }
    setExclusions(await api.trashExclusions().catch(() => exclusions));
  };

  if (!p) return <div className="scroll"><Empty>{err ?? "Loading…"}</Empty></div>;

  const direct = !!(p["permanent-delete"] || p["empty-trash"]);
  const thresholdIdx = Math.max(0, THRESHOLDS.indexOf(p["threshold-gb"]));
  const stale = agent?.installed && agent.program && !agent.program.includes(".app/Contents/MacOS/");

  return (
    <div className="scroll">
      <div className="page-head">
        <h1>Settings</h1>
        <p>Remembered here, and used by the background cleanup too.</p>
      </div>

      <div className="toolbar">
        <div className="grow">
          <Search value={q} onChange={setQ} placeholder="Search settings…" />
        </div>
      </div>

      {err && <Warn>{err}</Warn>}

      <Section query={q} terms={["What a cleanup does", "actually free the space", "trash", "permanent delete", "recoverable"]}>
      <Card title="What a cleanup does">
        <Switch checked={direct} onChange={(v) => save({ directCleanup: v })}
                label="Actually free the space" />
        <p className="card-note" style={{ marginTop: 8 }}>
          {direct
            ? "Regenerable caches are deleted outright and the Trash is emptied afterwards, so a cleanup frees what it says. None of it can be recovered — anything next to your own files still goes to the Trash."
            : "Everything eve removes goes to the Trash and eve never empties it, so nothing it does is irreversible. Nothing is actually freed until you empty the Trash yourself."}
        </p>
      </Card>
      </Section>

      <Section query={q} terms={["Background cleanup", "unattended", "agent", "schedule", "cadence", "threshold", "free space", "automatic"]}>
      <Card title="Background cleanup">
        <Switch checked={!!agent?.installed}
                onChange={async (v) => {
                  setAgent(await (v ? api.installAgent() : api.uninstallAgent()).catch((e) => { setErr(String(e)); return agent!; }));
                }}
                label="Clean up on its own when the disk runs low" />

        {stale && (
          <div style={{ marginTop: 10 }}>
            <Warn>
              The background cleanup is running a different copy of eve, which has
              its own permissions. Turn this off and on again to point it here.
            </Warn>
          </div>
        )}

        <div style={{ marginTop: 16, display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
          <span className="rw-sub" style={{ minWidth: 190 }}>Start when free space drops below</span>
          <div className="stepper">
            <button disabled={thresholdIdx <= 0}
                    onClick={() => save({ thresholdGb: THRESHOLDS[thresholdIdx - 1] })}>−</button>
            <span className="stepper-value">{p["threshold-gb"]} GB</span>
            <button disabled={thresholdIdx >= THRESHOLDS.length - 1}
                    onClick={() => save({ thresholdGb: THRESHOLDS[thresholdIdx + 1] })}>+</button>
          </div>
        </div>

        <div style={{ marginTop: 12, display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
          <span className="rw-sub" style={{ minWidth: 190 }}>At most one cleanup</span>
          <div className="segs">
            {CADENCE.map((c) => (
              <button key={c.secs}
                      className={`seg${p["cooldown-sec"] === c.secs ? " is-on" : ""}`}
                      onClick={() => save({ cooldownSec: c.secs })}>{c.label}</button>
            ))}
          </div>
          {!CADENCE.some((c) => c.secs === p["cooldown-sec"]) && (
            <Pill>every {duration(p["cooldown-sec"])}</Pill>
          )}
        </div>
      </Card>
      </Section>

      <Section query={q} terms={["Permissions", "full disk access", "app management", "notifications", "privacy"]}>
      <Card title="Permissions" action={<Btn kind="bare" size="sm" onClick={onRefreshPerms}>Re-check</Btn>}>
        <div className="rows" style={{ margin: "0 -16px" }}>
          {perms.map((x) => (
            <div key={x.permission} className={`perm is-${x.state}`}
                 style={{ background: "transparent", borderRadius: 0, padding: "10px 16px" }}>
              <span className="perm-ic">
                {x.state === "granted" ? "✓" : x.state === "denied" ? "▲" : "?"}
              </span>
              <div style={{ minWidth: 0 }}>
                <div className="perm-title">{x.title}{x.required ? "" : " · optional"}</div>
                <div className="perm-note">
                  {x.state === "granted" ? "Granted." : x.what_breaks}
                </div>
              </div>
              {/* Notifications are the one permission with a real API behind
                  them: macOS will show a prompt if eve asks. Sending someone
                  to a settings pane to switch on something they were never
                  asked about is the worse half of that trade. */}
              {/* macOS shows the notification dialog exactly once per app. If
                  it has already been answered, asking again does nothing at
                  all — so once eve is registered the honest button is the one
                  that takes you to where the answer can be changed. */}
              {x.state === "unknown" && x.permission === "notifications" && (
                <Btn size="sm" onClick={async () => {
                  const r = await api.requestNotifications().catch(() => "unknown");
                  onRefreshPerms();
                  // Declined, or the dialog never appeared because macOS had
                  // already recorded an answer: send them where it can change.
                  if (r !== "granted") api.openPrivacySettings("notifications");
                }}>
                  Ask me now
                </Btn>
              )}
              {x.state === "denied" && x.permission === "notifications" && (
                <Btn size="sm" onClick={() => api.openPrivacySettings("notifications")}>
                  Open Notifications
                </Btn>
              )}
              {x.state !== "granted" && x.permission !== "notifications" && (
                <Btn size="sm" onClick={() => api.openPrivacySettings(x.permission)}>Open Settings</Btn>
              )}
            </div>
          ))}
        </div>
      </Card>
      </Section>

      {/* The control whose absence meant "everytime eve runs, it breaks them".
          Grouped the way the catalog is, so the developer categories sit
          together and can be switched off together. Off here is off for the
          background run too — that is the one that did the damage. */}
      <Section query={q} terms={["What eve is allowed to clean", "categories", "developer tools", "rust", "xcode", "java", "kotlin", "gradle", "python", "caches"]}>
      <Card title="What eve is allowed to clean"
            sub={`${cats.filter((c) => c.enabled).length} of ${cats.length} on`}>
        <p className="card-note">
          Switching one off applies everywhere, including the unattended
          cleanup. Anything already off by default stays off until you opt in
          from the Clean screen.
        </p>
        {[...new Set(shownCats.map((c) => c.group))].map((g) => {
          const items = shownCats.filter((c) => c.group === g);
          const anyOn = items.some((c) => c.enabled);
          return (
            <div key={g} style={{ marginTop: 14 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <div className="rw-name" style={{ flex: 1 }}>{g}</div>
                <Btn kind="bare" size="sm"
                     onClick={() => items.forEach((c) => toggleCat(c.key, !anyOn))}>
                  {anyOn ? "Turn all off" : "Turn all on"}
                </Btn>
              </div>
              <div className="rows" style={{ margin: "4px -16px 0" }}>
                {items.map((c) => (
                  <div key={c.key} className="rw" style={{ gridTemplateColumns: "1fr 46px" }}>
                    <div style={{ minWidth: 0 }}>
                      <div className="rw-name truncate">
                        {c.title}
                        {!c.default_on && <Pill>opt-in</Pill>}
                      </div>
                      <div className="rw-sub">{c.description}</div>
                    </div>
                    <Switch checked={c.enabled} onChange={(v) => toggleCat(c.key, v)} label="" />
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </Card>
      </Section>

      <Section query={q} terms={["Never emptied from the Trash", "exclusions", "trash", "skip", "undeletable"]}>
      <Card title="Never emptied from the Trash" sub={`${exclusions.length}`}>
        <p className="card-note">
          Some Trash entries can never be deleted by anything — macOS Data
          Vaults, for instance, which not even root can unlink. Finder gives up
          on the whole Trash rather than skipping them; eve skips just these and
          empties the rest, and adds one here by itself whenever a sweep meets a
          new one. Every entry is yours: remove any of them.
        </p>
        <div className="rows" style={{ margin: "10px -16px 0" }}>
          {exclusions.map(([pattern, source]) => (
            <div key={pattern} className="rw" style={{ gridTemplateColumns: "1fr auto auto" }}>
              <span className="truncate mono" style={{ fontSize: 12 }}>{pattern}</span>
              <Pill>{source}</Pill>
              {/* Every one, including the ones eve suggested or added itself.
                  A permanent, unremovable list is the wrong shape for this:
                  the set is machine-specific and changes with macOS. */}
              <Btn kind="bare" size="sm"
                   onClick={async () => {
                     setExclusions(await api.removeTrashExclusion(pattern));
                     setP(await api.preferences());
                   }}>
                Remove
              </Btn>
            </div>
          ))}
        </div>
        <form style={{ display: "flex", gap: 8, marginTop: 12 }}
              onSubmit={(e) => {
                e.preventDefault();
                const v = adding.trim();
                if (!v) return;
                setAdding("");
                api.addTrashExclusion(v).then(setExclusions).catch((e) => setErr(String(e)));
              }}>
          <input className="input" style={{ flex: 1 }} value={adding} spellCheck={false}
                 placeholder="name or pattern, e.g. com.example.app*"
                 onChange={(e) => setAdding(e.target.value)} />
          <Btn kind="ghost" onClick={() => {
            const v = adding.trim();
            if (!v) return;
            setAdding("");
            api.addTrashExclusion(v).then(setExclusions).catch((e) => setErr(String(e)));
          }}>Add</Btn>
        </form>
      </Card>
      </Section>
    </div>
  );
}
