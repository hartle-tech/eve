// eve — desktop UI.
//
// No cleaning logic lives here. Every button calls the same engine the CLI
// uses, so the safety funnel cannot be bypassed by coming in through the
// window. This file only decides what to show.

const invoke = window.__TAURI__.core.invoke;
const $ = (id) => document.getElementById(id);

const state = {
  report: null,
  privileged: false,
  busy: false,
  armed: false,
};

function humanBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return i === 0 ? `${n} B` : `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

function setStatus(text, tone) {
  $("status").textContent = text;
  $("status-dot").className = `dot${tone ? ` is-${tone}` : ""}`;
}

/// Central place that decides whether Clean is pressable.
///
/// Previously each caller set `.disabled` inline, and one of them read
/// `state.busy` from inside the try block — before the `finally` had cleared
/// it — so the button was disabled after every scan and never came back. One
/// function that owns the rule means that cannot happen again.
function refreshCleanButton() {
  const total = totalBytes(state.report);
  const btn = $("clean");
  btn.disabled = state.busy || total === 0;
  btn.classList.toggle("is-armed", state.armed);
  btn.textContent = state.armed
    ? `Delete ${humanBytes(total)} — confirm`
    : total > 0
      ? `Clean up ${humanBytes(total)}`
      : "Clean up";
}

function totalBytes(report) {
  if (!report) return 0;
  return report.categories.reduce(
    (sum, c) => sum + c.reports.reduce((s, r) => s + (r.outcome?.bytes ?? 0), 0),
    0,
  );
}

function setBusy(on) {
  state.busy = on;
  $("rescan").disabled = on;
  refreshCleanButton();
}

// ─────────────────────────────────────────────────────────── views

function showView(name) {
  document.querySelectorAll(".view").forEach((v) =>
    v.classList.toggle("is-active", v.id === `view-${name}`),
  );
  document.querySelectorAll(".nav-item").forEach((b) => {
    const active = b.dataset.view === name;
    b.classList.toggle("is-active", active);
    if (active) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });

  if (name === "disk") loadDisk();
  if (name === "health") loadHealth();
  if (name === "history") loadHistory();
}

// ─────────────────────────────────────────────────────────── clean

function row({ title, sub, size, sizeClass, fraction, flag }) {
  const li = document.createElement("li");
  li.className = "row";

  const main = document.createElement("div");
  main.className = "row-main";

  const lead = document.createElement("div");
  lead.className = "row-lead";
  if (flag) {
    const f = document.createElement("span");
    f.className = `row-flag${flag === "ok" ? "" : ` is-${flag}`}`;
    lead.appendChild(f);
  }
  const t = document.createElement("span");
  t.className = "row-title";
  t.textContent = title;
  lead.appendChild(t);
  main.appendChild(lead);

  if (sub) {
    const s = document.createElement("span");
    s.className = "row-sub";
    s.textContent = sub;
    main.appendChild(s);
  }

  const meta = document.createElement("div");
  meta.className = "row-meta";

  if (fraction != null) {
    const bar = document.createElement("div");
    bar.className = "row-bar";
    const fill = document.createElement("span");
    fill.style.width = `${Math.max(3, fraction * 100)}%`;
    bar.appendChild(fill);
    meta.appendChild(bar);
  }

  const sz = document.createElement("span");
  sz.className = `row-size${sizeClass ? ` ${sizeClass}` : ""}`;
  sz.textContent = size;
  meta.appendChild(sz);

  li.append(main, meta);
  return li;
}

function renderReport(report, executed) {
  state.report = report;
  const total = totalBytes(report);

  $("reclaim-figure").textContent = humanBytes(total);

  if (report.free_after != null) {
    $("free-value").textContent = humanBytes(report.free_after);
    const fill = $("meter-fill");
    // Portion of a nominal 500 GB volume still free, clamped so the bar is
    // always visible.
    fill.style.width = `${Math.max(3, Math.min(100, (report.free_after / (500 * 1024 ** 3)) * 100))}%`;
    fill.classList.toggle("is-low", report.free_after < 5 * 1024 ** 3);
  }

  // What will go.
  const removable = report.categories
    .map((c) => ({
      title: c.title,
      needsRoot: c.needs_root,
      bytes: c.reports.reduce((s, r) => s + (r.outcome?.bytes ?? 0), 0),
      items: c.reports.filter((r) => (r.outcome?.bytes ?? 0) > 0).length,
    }))
    .filter((c) => c.bytes > 0)
    .sort((a, b) => b.bytes - a.bytes);

  const biggest = removable.length ? removable[0].bytes : 1;
  const list = $("remove-rows");
  list.innerHTML = "";
  $("remove-count").textContent = removable.length ? `${removable.length}` : "";

  if (!removable.length) {
    list.innerHTML = `<li class="empty">Nothing to reclaim right now.</li>`;
  }
  removable.forEach((c) =>
    list.appendChild(
      row({
        title: c.title,
        sub: `${c.items} item${c.items === 1 ? "" : "s"}${c.needsRoot ? " · needs your password" : ""}`,
        size: humanBytes(c.bytes),
        fraction: c.bytes / biggest,
      }),
    ),
  );

  // What was left alone. Collapsed by default — it is reassurance, not a task
  // list, and putting it in the reader's face made the app feel like a
  // spreadsheet.
  const held = [];
  report.categories.forEach((c) =>
    c.reports.forEach((r) => {
      if (!r.denial) return;
      const [kind, why] = describeDenial(r.denial);
      if (!kind) return;
      held.push({ path: r.path, kind, why });
    }),
  );

  const heldList = $("held-rows");
  heldList.innerHTML = "";
  $("held-count").textContent = held.length ? `${held.length}` : "0";
  if (!held.length) {
    heldList.innerHTML = `<li class="empty">Nothing was held back.</li>`;
  }
  held.slice(0, 250).forEach((h) =>
    heldList.appendChild(row({ title: h.path, sub: h.why, size: h.kind })),
  );

  const rootPending =
    !report.privileged_available && report.categories.some((c) => c.needs_root);

  if (executed) {
    $("hero-sub").textContent =
      "Recoverable items are in the Trash — empty it to actually free the space.";
    setStatus(`Reclaimed ${humanBytes(total)}`, "done");
  } else {
    $("hero-sub").textContent =
      total > 0
        ? `Across ${removable.length} categor${removable.length === 1 ? "y" : "ies"}. Nothing is deleted until you say so.`
        : "Your disk is already tidy.";
    setStatus(
      rootPending
        ? "Some system files need your password — turn on the switch above."
        : `${held.length} left alone`,
      null,
    );
  }
  refreshCleanButton();
}

/// A short label and a plain sentence for each refusal.
function describeDenial(d) {
  const key = typeof d === "string" ? d : Object.keys(d)[0];
  const v = typeof d === "string" ? {} : d[key];
  switch (key) {
    case "LiveOwner":
      return ["in use", v.detail];
    case "Protected":
      return ["protected", `${v.rule} — not cache`];
    case "SystemRestricted":
      return [null, null]; // macOS internals; numerous and not news
    case "ResolvesIntoProtected":
      return ["redirected", `resolves into ${v.resolved}`];
    case "SymlinkToProtected":
      return ["redirected", `points at ${v.target}`];
    case "UnattendedRefused":
      return ["needs you", `${v.tier} items need a person present`];
    case "NeedsPrivilege":
      return ["needs password", "turn on system files above"];
    case "Whitelisted":
      return [null, null];
    default:
      return ["skipped", key];
  }
}

async function scan() {
  if (state.busy) return;
  state.armed = false;
  setBusy(true);
  setStatus("Scanning…", "busy");
  try {
    const report = await invoke("scan", { request: { privileged: state.privileged } });
    setBusy(false); // clear before rendering, so the button reflects the result
    renderReport(report, false);
  } catch (e) {
    setBusy(false);
    setStatus(`Scan failed: ${e}`, "alert");
  }
}

async function clean() {
  if (state.busy) return;

  // Arm first. A single click that deletes gigabytes is the one place this
  // app should be slower than it could be.
  if (!state.armed) {
    state.armed = true;
    refreshCleanButton();
    setStatus("Click again to confirm.", "alert");
    return;
  }

  state.armed = false;
  setBusy(true);
  setStatus(
    state.privileged ? "Cleaning — you may be asked to authenticate…" : "Cleaning…",
    "busy",
  );
  try {
    const report = await invoke("clean", { request: { privileged: state.privileged } });
    setBusy(false);
    renderReport(report, true);
  } catch (e) {
    setBusy(false);
    setStatus(`Clean failed: ${e}`, "alert");
  }
}

// ───────────────────────────────────────────────────── other views

async function loadDisk() {
  const el = $("disk-bars");
  el.innerHTML = `<li class="empty">Measuring…</li>`;
  try {
    const a = await invoke("disk_analysis", { path: null });
    const ranked = [...a.entries].sort((x, y) => y.bytes - x.bytes).slice(0, 25);
    const biggest = ranked.length ? ranked[0].bytes || 1 : 1;
    el.innerHTML = ranked.length ? "" : `<li class="empty">Nothing to show.</li>`;
    ranked.forEach((e) =>
      el.appendChild(
        row({
          title: e.name,
          sub: e.cleanable || undefined,
          size: humanBytes(e.bytes),
          fraction: e.bytes / biggest,
        }),
      ),
    );
  } catch (e) {
    el.innerHTML = `<li class="empty">Could not read the disk: ${e}</li>`;
  }
}

async function loadHealth() {
  try {
    const s = await invoke("system_status");
    $("health-host").textContent =
      `${s.host} · ${s.os} · up ${Math.floor(s.uptime_secs / 3600)}h · ${s.cpu_count} cores`;

    const f = $("findings");
    f.innerHTML = "";
    s.health.forEach((h) =>
      f.appendChild(
        row({
          title: h.subject,
          sub: h.detail,
          size: "",
          flag: h.level === "warn" ? "warn" : h.level === "critical" ? "critical" : "ok",
        }),
      ),
    );

    const v = $("volumes");
    v.innerHTML = "";
    s.volumes.forEach((vol) =>
      v.appendChild(
        row({
          title: vol.mount,
          sub: `${Math.round((1 - vol.available / vol.total) * 100)}% used`,
          size: `${humanBytes(vol.available)} free`,
          flag: vol.available < 5 * 1024 ** 3 ? "critical" : vol.available < 15 * 1024 ** 3 ? "warn" : "ok",
        }),
      ),
    );
  } catch (e) {
    $("health-host").textContent = `Could not read system status: ${e}`;
  }
}

async function loadHistory() {
  const el = $("log");
  el.innerHTML = "";
  try {
    const entries = await invoke("history");
    const real = entries.filter((e) => !e.dry_run && !e.error);
    const total = real.reduce((s, e) => s + e.bytes, 0);
    $("history-total").textContent = entries.length
      ? `${humanBytes(total)} reclaimed across ${entries.length} entries.`
      : "eve has not deleted anything yet.";

    if (!entries.length) el.innerHTML = `<li class="empty">Nothing yet.</li>`;
    entries
      .slice()
      .reverse()
      .slice(0, 400)
      .forEach((e) =>
        el.appendChild(
          row({ title: e.path, sub: e.category, size: humanBytes(e.bytes) }),
        ),
      );
  } catch (e) {
    $("history-total").textContent = `Could not read the journal: ${e}`;
  }
}

// ───────────────────────────────────────────────────────────── wire

document.querySelectorAll(".nav-item").forEach((b) =>
  b.addEventListener("click", () => showView(b.dataset.view)),
);
$("rescan").addEventListener("click", scan);
$("clean").addEventListener("click", clean);
$("privileged").addEventListener("change", (e) => {
  state.privileged = e.target.checked;
  scan();
});
$("held-toggle").addEventListener("click", () => {
  const body = $("held-body");
  const open = body.hasAttribute("hidden");
  if (open) body.removeAttribute("hidden");
  else body.setAttribute("hidden", "");
  $("held-toggle").setAttribute("aria-expanded", String(open));
});

// Clicking anywhere else cancels an armed delete.
document.addEventListener("click", (e) => {
  if (state.armed && e.target.closest("#clean") === null) {
    state.armed = false;
    refreshCleanButton();
    setStatus("Cancelled.", null);
  }
});

scan();
