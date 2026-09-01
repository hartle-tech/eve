# Security policy

eve deletes files, and for two categories it does so as root. That makes the
interesting bugs here safety bugs: anything that lets a path reach a deletion it
should not have reached, or lets a caller obtain authority it was not granted.

Please report vulnerabilities privately to
[security@hartle.tech](mailto:security@hartle.tech) before opening a public
issue. Include the eve version, your macOS version, whether you were using the
app or the CLI, and the smallest reproduction you can manage.

## In scope

- **Reaching a protected path.** Anything that gets a delete past the path
  validation or the protection policy — a symlinked ancestor, a `..` component
  that survives normalisation, a Unicode form that compares unequal to the deny
  rule, or a race between the check and the unlink.
- **The privileged worker.** The worker re-runs the whole funnel as root and
  accepts a typed plan rather than a shell string. A way to make it act on a
  request the policy forbids, to reach it from a process that is not its parent,
  or to keep it alive past the parent's exit, is in scope.
- **The sudoers grant.** The Ansible role installs a root-owned helper. Anything
  that makes a user-writable binary satisfy the ownership check — or that
  reaches the helper other than through the documented grant — is in scope.
- **Escalation of the tier gate.** `destructive` and `never-auto` categories must
  be unreachable from an unattended run whatever any configuration file says.
  Any path that reaches them from `eve autoclean` is a vulnerability, not a
  configuration mistake.
- **The Trash contract.** eve refuses rather than escalating to a permanent
  unlink when the Trash is unavailable. A case where it escalates silently is in
  scope even if nothing was lost in your reproduction.
- **The journal.** A deletion that completes without being recorded, or a way to
  rewrite records that are meant to be append-only.
- **The unattended lock.** Stealing a live run's lock, or defeating the cooldown
  so a run can be made to re-fire.

## Not in scope

- eve removing something it says it removes. A cache you wanted to keep belongs
  in `eve config exclude`, and a category you disagree with is a normal issue.
- Needing Full Disk Access. TCC is SIP-protected; no program can grant itself a
  permission, and eve deliberately does not try.
- Anything that requires an attacker who already has root on the machine.

## Please do not send

Actual file listings from your disk, disk images, or the contents of anything
eve reported on. A redacted path shape, the category name, and the version are
enough to reproduce almost everything here — and if they are not, we will ask
for something specific rather than for everything you have.

## What happens next

We will acknowledge receipt, reproduce without widening the unsafe surface, and
agree a disclosure window with you. Fixes are published to the public GitHub
repository, and reporters are credited unless anonymity is requested.
