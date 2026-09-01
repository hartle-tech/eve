# Contributing to eve

eve exists because the disk-cleaning tools on macOS are either too timid to
reclaim anything worth reclaiming, or careless enough that you cannot leave them
alone with your files. Contributions are welcome — especially from people whose
Macs are set up differently from ours.

Good first contributions:

- **A category that eve misses.** Something on your disk that is genuinely
  regenerable, with the path shape and roughly what it costs you.
- **A category that eve gets wrong.** Somewhere it offers to delete something you
  would have wanted, or refuses something it should reach. This is the more
  valuable of the two.
- **An uninstaller leftover** that eve fails to associate with its app.
- **A protection rule** for a location we have not thought of.
- Documentation, and honest reports of what eve did on a machine unlike ours.

## The rule that governs everything else

**No deletion gets a second path.** Every removal — CLI, TUI, app, unattended
run, or the root worker — goes through the same funnel and the same five gates.
A change that adds a shortcut around it will not be merged, however much simpler
it looks. If a gate is in your way, the gate is what to change.

Read [`docs/SAFETY.md`](docs/SAFETY.md) before touching anything under
`eve-core` or `eve-engines`. It is short, and it is the design.

## Before you start

- New categories are declared in the catalog, with a tier, not written as code
  in a sweep. The tier belongs to the **target**, not to whoever is asking.
- A category that could ever match user data is `never-auto`. If you find
  yourself arguing for an exception, that is the signal to stop and open an
  issue instead.
- Anything that runs as root goes through the existing worker. Do not add a
  second privileged path, and do not pass a shell string across that boundary.
- Sizes are `st_blocks * 512`. `st_size` is what the inode advertises, not what
  the volume gives back, and mixing the two silently makes every number wrong.

## Development

Requires macOS 14 or later and Rust 1.85+.

```sh
cargo fmt --all -- --check
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The app bundle:

```sh
scripts/bundle-app.sh --sign "Developer ID Application: …"   # omit to ad-hoc sign
cp -R dist/eve.app /Applications/
```

A stable signature matters more than it looks: macOS keys Full Disk Access to
it, so an ad-hoc build loses every grant on every rebuild.

## Tests

A change to the funnel needs a test that fails without it. Please make the test
assert on the **decision**, not on the plumbing — "this path is refused" rather
than "this function returned `None`" — because the plumbing is exactly the part
that gets refactored later.

Take particular care that a test does not share its constant with the code it
checks. A fixture built from the same table the implementation reads cannot fail
when the table is wrong, and will pass forever while the behaviour is broken.

## Reporting

Please include your macOS version, whether it was the app or the CLI, and the
relevant lines from `eve history`. Redact paths as much as you like — the shape
is what matters.

Security-sensitive reports go to [security@hartle.tech](mailto:security@hartle.tech)
first; see [SECURITY.md](SECURITY.md).

## Licence

Contributions are accepted under [Apache-2.0](LICENSE), the licence eve is
distributed under.
