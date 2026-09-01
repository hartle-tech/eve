/// The one place that talks to Rust.
///
/// Every command is typed here so a rename on either side is a compile error
/// rather than an `undefined` three screens away. The arg names are camelCase
/// because Tauri converts them; the *payload* keys stay kebab-case because
/// serde renames those.

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

const bridge = (): Invoke => {
  const t = (window as any).__TAURI__;
  if (!t?.core?.invoke) {
    // Running in a plain browser (the headless harness, or `vite dev` without
    // Tauri). Failing loudly beats every screen showing an empty state.
    return (() => Promise.reject(new Error("no Tauri bridge"))) as Invoke;
  }
  return t.core.invoke as Invoke;
};

export const invoke: Invoke = (cmd, args) => bridge()(cmd, args);

// ─────────────────────────────────────────────────────────── types

export type Disposition = "trash" | "permanent" | "empty-contents" | "permanent-contents";
export type Tier = "safe" | "review" | "privileged" | "destructive" | "never-auto";

export interface ExecOutcome {
  path: string;
  disposition: Disposition;
  bytes: number;
  files: number;
  complete: boolean;
  dry_run: boolean;
  error: string | null;
  /// Individual children a sweep could not remove. One stuck item is not a
  /// failed sweep, so these are kept apart from `error`.
  failures: string[];
  /// Names macOS will never let anything delete. Narrower than `failures`:
  /// a file a running process holds open is temporary and belongs nowhere
  /// near this list.
  permanently_stuck: string[];
}

export type Denial = string | Record<string, any>;

export interface FunnelReport {
  path: string;
  category: string;
  tier: Tier;
  denial: Denial | null;
  outcome: ExecOutcome | null;
}

export interface CategoryResult {
  key: string;
  title: string;
  description: string;
  group: string;
  tier: Tier;
  needs_root: boolean;
  reports: FunnelReport[];
  commands: { note: string; ran: boolean; ok: boolean; detail: string | null }[];
}

export interface CleanReport {
  dry_run: boolean;
  categories: CategoryResult[];
  free_before: number | null;
  free_after: number | null;
  privileged_available: boolean;
  /// Trash exclusions this run added by itself, having proved those entries
  /// undeletable. Surfaced so the list never grows silently.
  newly_excluded: string[];
}

export type MemoryMode = "safe" | "unsafe";
export type Pressure = "normal" | "warning" | "critical" | "unknown";

export interface MemorySnapshot {
  total: number;
  free: number;
  active: number;
  inactive: number;
  speculative: number;
  wired: number;
  compressed: number;
  file_backed: number;
  swap_total: number;
  swap_used: number;
  pressure: Pressure;
}

export interface BoostOption {
  key: string;
  title: string;
  mode: MemoryMode;
  needs_root: boolean;
  detail: string;
  caveat: string;
}

export interface BoostResult {
  key: string;
  mode: MemoryMode;
  ran: boolean;
  ok: boolean;
  before: MemorySnapshot;
  after: MemorySnapshot;
  freed: number;
  detail: string | null;
}

export interface MemoryReport {
  snapshot: MemorySnapshot;
  boosts: BoostOption[];
  fixed_costs: { path: string; bytes: number; why: string }[];
}

export interface Preferences {
  "empty-trash": boolean;
  "empty-trash-at": "start" | "end";
  "permanent-delete": boolean;
  "trash-exclusions": string[];
  "disabled-categories": string[];
  "threshold-gb": number;
  "cooldown-sec": number;
}

/// One cleanable category and whether it is switched on.
export interface CategoryInfo {
  key: string;
  title: string;
  description: string;
  group: string;
  tier: string;
  enabled: boolean;
  default_on: boolean;
}

export type PermissionState = "granted" | "denied" | "unknown";

/// A process holding something open under a path — who to ask to let go.
export interface Holder {
  pid: number;
  name: string;
}

export type MachineKind = "containers" | "virtual-machine" | "emulator";

/// A container store, VM disk or emulator image — the biggest things on a
/// developer's disk that no cache cleaner looks at.
export interface Machine {
  kind: MachineKind;
  name: string;
  path: string;
  bytes: number;
  complete: boolean;
  cost: string;
  better_command: string | null;
}

/// An app standing between you and an empty Trash.
export interface Blocker {
  pid: number;
  name: string;
  entries: string[];
  bytes: number;
}

export interface PermissionStatus {
  permission: "full-disk-access" | "app-management" | "notifications";
  state: PermissionState;
  title: string;
  what_breaks: string;
  required: boolean;
  settings_url: string;
  look_for: string;
}

export interface AgentStatus {
  installed: boolean;
  loaded: boolean;
  plist: string;
  program: string | null;
}

export interface JournalEntry {
  at: number;
  path: string;
  category: string;
  tier: string;
  principal: string;
  bytes: number;
  files: number;
  disposition: Disposition;
  dry_run: boolean;
  error: string | null;
}

export interface HistoryPage {
  entries: JournalEntry[];
  total: number;
}

export interface Volume {
  mount: string;
  total: number;
  available: number;
}

export interface Status {
  host: string;
  os: string;
  uptime_secs: number;
  cpu_count: number;
  cpu_usage: number;
  load: [number, number, number];
  mem_used: number;
  mem_total: number;
  swap_used: number;
  swap_total: number;
  volumes: Volume[];
  health: { subject: string; detail: string; level: "ok" | "warn" | "critical" }[];
  top_processes: { pid: number; name: string; cpu: number; memory: number; exe: string | null }[];
}

export interface AppInfo {
  name: string;
  path: string;
  bundle_id: string | null;
  bytes: number;
  /// Installed by a package, so it is root-owned and this user cannot move it.
  /// POSIX, not a permission anyone can grant in System Settings.
  needs_admin: boolean;
  kind: AppKind;
  /// False only for the sealed system volume. Unlike `needs_admin`, no
  /// password changes this.
  removable: boolean;
}

export type AppKind = "development" | "user" | "apple-extra" | "mac-os";

// ────────────────────────────────────────────────────────── commands

export const api = {
  scan: (privileged: boolean) => invoke<CleanReport>("scan", { request: { privileged } }),
  clean: (privileged: boolean) => invoke<CleanReport>("clean", { request: { privileged } }),
  preferences: () => invoke<Preferences>("preferences"),
  setPreferences: (p: {
    directCleanup: boolean;
    thresholdGb: number;
    cooldownSec: number;
    trashExclusions: string[];
  }) => invoke<Preferences>("set_preferences", p),
  trashExclusions: () => invoke<[string, string][]>("trash_exclusions"),
  categories: () => invoke<CategoryInfo[]>("categories"),
  addTrashExclusion: (pattern: string) =>
    invoke<[string, string][]>("add_trash_exclusion", { pattern }),
  removeTrashExclusion: (pattern: string) =>
    invoke<[string, string][]>("remove_trash_exclusion", { pattern }),
  lockedPaths: () => invoke<string[]>("locked_paths"),
  setLocked: (path: string, locked: boolean) =>
    invoke<string[]>("set_locked", { path, locked }),
  clearHistory: () => invoke<number>("clear_history"),
  setCategoryEnabled: (key: string, enabled: boolean) =>
    invoke<Preferences>("set_category_enabled", { key, enabled }),
  permissions: () => invoke<PermissionStatus[]>("permissions"),
  recheckPermissions: () => invoke<PermissionStatus[]>("recheck_permissions"),
  openPrivacySettings: (permission: string) =>
    invoke<void>("open_privacy_settings", { permission }),
  agentStatus: () => invoke<AgentStatus>("agent_status"),
  installAgent: () => invoke<AgentStatus>("install_agent"),
  uninstallAgent: () => invoke<AgentStatus>("uninstall_agent"),
  relaunch: () => invoke<void>("relaunch"),
  status: () => invoke<Status>("system_status"),
  history: (offset: number, limit: number) =>
    invoke<HistoryPage>("history", { offset, limit }),
  browse: (path: string | null) => invoke<BrowseResult>("browse", { path }),
  refreshSizes: (path: string) => invoke<void>("refresh_sizes", { path }),
  deletePaths: (paths: string[]) => invoke<DeleteOutcome[]>("delete_paths", { paths }),
  revealInFinder: (path: string) => invoke<void>("reveal_in_finder", { path }),
  revealInTerminal: (path: string) => invoke<void>("reveal_in_terminal", { path }),
  owningProcesses: (path: string) => invoke<Holder[]>("owning_processes", { path }),
  killProcess: (pid: number) => invoke<void>("kill_process", { pid }),
  requestNotifications: () => invoke<PermissionState>("request_notifications"),
  trashBlockers: () => invoke<Blocker[]>("trash_blockers"),
  listMachines: () => invoke<Machine[]>("list_machines"),
  removeMachines: (paths: string[], execute: boolean) =>
    invoke<DeleteOutcome[]>("remove_machines", { paths, execute }),
  listApps: (includeSystem = false) =>
    invoke<AppInfo[]>("list_apps", { includeSystem }),
  uninstallApps: (paths: string[], execute: boolean, privileged = false) =>
    invoke<UninstallBatch>("uninstall_apps", { paths, execute, privileged }),
  memoryReport: () => invoke<MemoryReport>("memory_report"),
  runBoost: (key: string, execute: boolean) =>
    invoke<BoostResult>("run_boost", { key, execute }),
};

export interface BrowseEntry {
  name: string;
  path: string;
  bytes: number;
  is_dir: boolean;
  children: number;
  complete: boolean;
}

export interface BrowseResult {
  path: string;
  parent: string | null;
  entries: BrowseEntry[];
  total: number;
  complete: boolean;
}

export interface UninstallBatch {
  apps: { name: string; path: string; bytes: number; items: number; needs_admin: boolean }[];
  reports: FunnelReport[];
  /// What the plan came to — a forecast.
  total_bytes: number;
  /// What was actually removed. Never show `total_bytes` as a result: with
  /// /Applications refusing every bundle, this screen used to report the full
  /// size of an app that was still in the Dock.
  freed_bytes: number;
  problems: string[];
  executed: boolean;
}

/// What happened to one path picked in the Disk view.
///
/// `ok` is the whole answer. A `FunnelReport` with no denial only means the
/// funnel allowed it; the executor refuses too, and later.
export interface DeleteOutcome {
  path: string;
  bytes: number;
  ok: boolean;
  problem: string | null;
}
