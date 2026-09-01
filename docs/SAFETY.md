# Why eve is careful

Every deletion — from the CLI, the TUI, an unattended run, or root — passes the
same five gates. **There is no second path.**

## The five gates

### 1 · Path validation

Absolute paths only; `..` rejected as a whole component (while `name..files`,
which Firefox really creates, is allowed); control characters rejected; symlink
targets judged rather than skipped.

Plus an **ancestor-symlink guard**. Protection rules match on the literal path
string, so if any ancestor is a symlink the string looks innocent while the
actual delete follows the link somewhere else — a redirected `~/Library/Caches`
would let a cache sweep walk into `~/Documents`. eve canonicalises the parent
and re-runs the deny predicates on the resolved path. Deny-only: resolution
never grants permission the literal path lacked.

### 2 · Protection policy

System roots, other users' homes, mounted volumes, and your documents, photos,
keys and iCloud files. A category may declare an exemption for one specific
subtree, and that declaration is visible in the catalog rather than buried in
code.

### 3 · A live-owner check that fails closed

eve refuses to delete a cache whose owning process is still running, or whose
SQLite database has a live write-ahead log. "I could not tell" counts as "still
running": an unreadable process table or a missing `lsof` refuses rather than
proceeds.

This one matters more than it sounds. Deleting an open SQLite cache can send
the owning helper into a loop writing to unlinked files *until the volume
fills*. A cleaner that fires when the disk is nearly full and then makes it
worse is not a cleaner.

### 4 · Trash by default

Deletions are recoverable. If the Trash is unavailable, eve **refuses** rather
than silently escalating to a permanent unlink — a caller who asked for a
recoverable delete and quietly got an irrecoverable one has been lied to.
Permanent removal is used only where the Trash is meaningless, such as
root-owned system paths.

There is one deliberate exception, and it is off until you ask for it. A Trash
that is never emptied means the space is never really reclaimed, so
`eve config empty-trash on` makes emptying it part of every clean. It runs
*first*, before the same run refills it — so what this run removes still lands
in the Trash and stays recoverable until the next one, and no byte is ever
counted both as moved and as deleted.

### 5 · An append-only journal

`eve history` shows what was removed, when, how large it was, and under whose
authority.

## Risk tiers

Every category carries a tier, and the tier is a property of the **target**,
not of whoever is asking:

| Tier | Meaning | Unattended? |
|---|---|---|
| `safe` | regenerable caches | yes |
| `review` | adjacent to user data | no |
| `privileged` | needs root | yes |
| `destructive` | app removal, system assets | no |
| `never-auto` | user data misfiled as cache | **never** |

iOS device backups are `never-auto`. They are photos and videos, and they are
TCC-protected — so they measure as 0 bytes and their deletion would not even be
visible in a log. No flag, forgotten or otherwise, lets an unattended run reach
them.

## Privileged operations

eve does not ask for your password more than once, and never stores it.

When a category needs root, eve spawns **one worker for the session** via
`sudo` (with Touch ID, if `pam_tid` is configured). The worker holds root and
talks to the parent over inherited file descriptors that no other process can
connect to. When eve exits, the pipe closes and root goes away with it.

The worker **re-runs the entire funnel as root**. It does not trust the
parent's verdict, only its request — so a compromised or merely buggy parent
cannot talk root into deleting something the policy forbids. What crosses the
boundary is a typed, validated plan, never a shell string.

## What macOS will not let you delete

macOS refuses to remove some Trash entries while the process that made them is
running — and Finder responds by abandoning the *whole* Trash rather than
skipping the offending item, which is how a Trash reaches tens of gigabytes
with no way to empty it from the UI. eve skips just those entries, names the
pattern responsible in its output, and empties the rest.

The caches of `siriactionsd`, `WorkflowKit.BackgroundShortcutRunner` and
`quicklook.ThumbnailsAgent` are excluded out of the box. `eve config exclude
<glob>` adds your own; `eve config` lists them all with their source.
