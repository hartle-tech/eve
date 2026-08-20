# eve

**Reclaim disk space on macOS without losing anything you wanted.**

eve is a cleaner, disk analyser, app uninstaller and system monitor for macOS,
written in Rust. It reaches the places a user-level cleaner cannot — the
hibernation image, the unified log store, leftover installer packages, hidden
data-volume directories — and it refuses to touch the things that only look
like cache.

```
eve clean                 # preview; nothing is deleted
eve clean --execute       # do it
eve clean --privileged    # include the categories that need root
eve analyze ~/Projects    # what is actually using the space
eve uninstall "Some App"  # the app and its leftovers
eve status                # health, volumes, top processes
eve history               # everything eve has ever deleted
eve                       # the interactive TUI
```

<!-- funding:begin -->
<p align="center"><strong>Free, and it stays free.</strong> If it saved you an afternoon, this is where you can say so:</p>
<p align="center">
  <a href="https://github.com/sponsors/code-hartle-tech"><img alt="Sponsor" src="https://img.shields.io/badge/Sponsor-GitHub-ea4aaa?style=for-the-badge&logoColor=white&labelColor=0b0f10&logo=githubsponsors"></a>
  <a href="https://patreon.com/HARTLETECH"><img alt="Patreon" src="https://img.shields.io/badge/Patreon-support-f96854?style=for-the-badge&logoColor=white&labelColor=0b0f10&logo=patreon"></a>
  <a href="https://liberapay.com/hartle.tech/donate"><img alt="Liberapay" src="https://img.shields.io/badge/Liberapay-donate-f6c915?style=for-the-badge&logoColor=white&labelColor=0b0f10&logo=liberapay"></a>
  <a href="https://ko-fi.com/hartletech"><img alt="Ko-fi" src="https://img.shields.io/badge/Ko--fi-support-ff5e5b?style=for-the-badge&logoColor=white&labelColor=0b0f10&logo=kofi"></a>
  <a href="https://wise.com/pay/business/hartletechunipessoallda"><img alt="Wise" src="https://img.shields.io/badge/Wise-donate-9fe870?style=for-the-badge&logoColor=white&labelColor=0b0f10&logo=wise"></a>
  <a href="https://paypal.me/hartletech"><img alt="PayPal" src="https://img.shields.io/badge/PayPal-donate-003087?style=for-the-badge&logoColor=white&labelColor=0b0f10&logo=paypal"></a>
  <a href="https://buy.stripe.com/5kQ8wR3Wm1sjbKW15E9fW01"><img alt="Stripe" src="https://img.shields.io/badge/Stripe-donate-635bff?style=for-the-badge&logoColor=white&labelColor=0b0f10&logo=stripe"></a>
</p>
<!-- funding:end -->

## Why it is careful

Every deletion — from the CLI, the TUI, an unattended run, or root — passes the
same five gates. There is no second path.

1. **Path validation.** Absolute paths only; `..` rejected as a whole component
   (while `name..files`, which Firefox really creates, is allowed); control
   characters rejected; symlink targets judged rather than skipped.

   Plus an **ancestor-symlink guard**. Protection rules match on the literal
   path string, so if any ancestor is a symlink the string looks innocent while
   the actual delete follows the link somewhere else — a redirected
   `~/Library/Caches` would let a cache sweep walk into `~/Documents`. eve
   canonicalises the parent and re-runs the deny predicates on the resolved
   path. Deny-only: resolution never grants permission the literal path lacked.

2. **Protection policy.** System roots, other users' homes, mounted volumes,
   and your documents, photos, keys and iCloud files. A category may declare an
   exemption for one specific subtree, and that declaration is visible in the
   catalog rather than buried in code.

3. **A live-owner check that fails closed.** eve refuses to delete a cache
   whose owning process is still running, or whose SQLite database has a live
   write-ahead log. "I could not tell" counts as "still running": an unreadable
   process table or a missing `lsof` refuses rather than proceeds.

   This one matters more than it sounds. Deleting an open SQLite cache can send
   the owning helper into a loop writing to unlinked files *until the volume
   fills*. A cleaner that fires when the disk is nearly full and then makes it
   worse is not a cleaner.

4. **Trash by default.** Deletions are recoverable. If the Trash is
   unavailable, eve **refuses** rather than silently escalating to a permanent
   unlink — a caller who asked for a recoverable delete and quietly got an
   irrecoverable one has been lied to. Permanent removal is used only where the
   Trash is meaningless, such as root-owned system paths.

5. **An append-only journal.** `eve history` shows what was removed, when, how
   large it was, and under whose authority.

### Risk tiers

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

## Unattended cleaning

`eve autoclean` is a low-disk trigger, intended to run from a LaunchAgent.
launchd has no low-disk event, so it polls; the common case is one `statfs` and
an immediate exit. It holds a lock whose staleness is judged by whether the
recorded pid is alive rather than by age, so a long legitimate run cannot have
its lock stolen, and it enforces a cooldown so a persistent problem does not
re-fire forever.

When it finishes, it tells you the truth: if it reclaimed very little and the
disk is *still* low, it says so plainly, because that means the space is being
used by something that is not cache and re-running will not help.

## Install

Requires macOS 14+ and Rust 1.85+.

```sh
git clone https://github.com/hartle-tech/eve
cd eve
cargo build --release
install -m 755 target/release/eve ~/.local/bin/eve
```

The Ansible role in `ansible/` builds and installs eve, the LaunchAgent, and a
root-owned privileged helper with a narrowly scoped sudoers grant:

```sh
cd ansible
ansible-playbook -i hosts.ini autoclean.yml --ask-become-pass
```

The sudoers grant names a **root-owned, non-user-writable** copy of eve. That
distinction is the whole point: a grant that names a user-writable binary is
not a security boundary, because anything able to write that file gains
passwordless root. eve verifies the ownership itself before using the helper
and falls back to re-executing its own binary if the check fails.

### Full Disk Access

Much of `~/Library` is TCC-protected. Without Full Disk Access, protected paths
measure as 0 bytes and are silently skipped — which is exactly how an important
directory hides. Grant it to your terminal (or to eve) in
**System Settings → Privacy & Security → Full Disk Access**.

## Status

Working: `clean`, `analyze`, `uninstall`, `installer`, `optimize`, `status`,
`history`, `whitelist`, `autoclean`, and the TUI. 92 tests.

Planned: a self-contained `.app`, and an `SMAppService` daemon to replace the
sudoers grant entirely.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

HARTLE.TECH · contact@hartle.tech
