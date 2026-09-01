# Install

## The app

1. Download `eve.app`, drag it into **Applications**, open it.
2. It asks for Full Disk Access and opens that exact Settings page. Flip the
   switch.
3. eve restarts itself and is ready.

That is the whole setup. Nothing to build, no Terminal, no toolchain. Turning
on **Settings → Run in the background** installs the scheduled cleanup too,
and it needs no extra permission because it runs the same file you just
allowed.

macOS grants access to a *program*, identified by its signature — so a helper
binary next to the app would be a second program needing a second grant in a
second place. eve's background job is the app's own executable, invoked with
`autoclean`, which exits without ever opening a window. One file, one grant.

If you decline, eve keeps working on whatever it can still reach and shows a
warning triangle beside each thing that will not work, with a button that
opens the right page. It never asks twice.

## The command-line tool

Requires macOS 14+ and Rust 1.85+.

```sh
git clone https://github.com/hartle-tech/eve
cd eve
cargo build --release
install -m 755 target/release/eve ~/.local/bin/eve

eve permissions --fix     # opens the right pane for whatever is missing
eve agent install         # the scheduled cleanup, no Ansible needed
```

The CLI is a **different program** to macOS than the app, so it needs its own
Full Disk Access grant. If you have both and want one grant to cover
everything, point the background job at the app:

```sh
eve agent install --program /Applications/eve.app/Contents/MacOS/eve
eve agent                 # shows which executable launchd will run
```

## Building the app yourself

```sh
scripts/bundle-app.sh --sign "Developer ID Application: …"   # omit to ad-hoc sign
cp -R dist/eve.app /Applications/
```

A signature that stays the same between builds matters more than it sounds:
macOS keys permissions to it, so an ad-hoc binary — whose identifier is a
build hash — loses every grant on every rebuild.
`scripts/create-signing-identity.sh` walks through getting a certificate,
self-signed or Developer ID.

## The privileged extras

Two categories need root: the hibernation image and the unified log store.
They are optional, and the Ansible role in `ansible/` installs a root-owned
helper with a narrowly scoped sudoers grant for them:

```sh
cd ansible
ansible-playbook -i hosts.ini autoclean.yml --ask-become-pass
```

The grant names a **root-owned, non-user-writable** copy of eve. A grant
naming a user-writable binary is not a security boundary, because anything
able to write that file gains passwordless root. eve verifies the ownership
itself before using the helper.

## Full Disk Access, and why nothing can automate it

TCC is SIP-protected: no program can grant itself a permission, and no script
can grant one either. Only a person, in System Settings. What eve *can* do is
make that as short as macOS allows — request the access first, so it appears
in the list instead of having to be dragged in from a hidden directory; open
its exact pane; and restart afterwards, because macOS reads these decisions
when a process starts and an app that has just been allowed still cannot act
on it.

`~/.Trash` sits behind the same wall, so emptying the Trash does nothing at
all until this is granted. eve says so rather than reporting an empty Trash: a
refused read is reported as `could not read …`, never as "there was nothing
there".

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

### Durable consent

The unattended tier gate exists so that no caller reaches a dangerous tier
because someone forgot a flag. A setting you stored deliberately is the
opposite of forgetting, so a stored preference can lift that gate — for that
one category, and only up to `review`. `destructive` and `never-auto` stay
unreachable from an unattended run whatever any file says, which is what keeps
iPhone backups structurally out of the LaunchAgent's reach.

Today exactly one setting works this way: `empty-trash`. It has to, because the
unattended run is the one filling the Trash, so it is the one that has to empty
it. `--skip trash` still overrides it for a single run.
