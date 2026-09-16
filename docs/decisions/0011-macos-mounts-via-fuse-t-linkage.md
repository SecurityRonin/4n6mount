# 11. On macOS the FUSE mechanism is chosen by LINKAGE, not by a flag or a feature — and on macOS 27 that mechanism is FUSE-T

Date: 2026-09-16
Status: Accepted — FUSE-T build verified end to end; `--fuse-backend` removed, `--list-fuse-backends` retained

## Context

`4n6mount` mounts through the `fuser` crate, which links `libfuse`. On macOS 27
(build 26A5425a) **no mount worked at all**, for any image, with
`Operation not permitted`.

Four independent programs were tried on the same machine, all linking
`/usr/local/lib/libfuse.2.dylib` (macFUSE 5.4.0):

| Program | Result |
|---|---|
| `4n6mount` (fuser 0.16) | `EPERM` |
| `minfuse` — 40 lines, none of our code | `Unspecified Error`, no errno |
| the same against fuser **0.18** | identical |
| **`ewfmount`** (libewf, third-party) | `volicon: missing 'iconpath' option` |

`ewfmount` is what settles it: a mature tool unrelated to this project, failing
with a macFUSE **option-parsing** error. macFUSE 5.4.0's libfuse2 compatibility
layer is broken for its clients on this OS. Nothing in this repository could fix
that.

Five plausible causes were investigated and fixed first. **None was the
blocker**, and each cost a reboot or an hour:

- kext staged but never approved
- approved for 5.3.3 while 5.4.0 was installed — a new version needs its own
  approval; the *staged* version is what loads
- loaded with `kmutil load`, which bypasses macFUSE's own `load_macfuse` and
  leaves `tunables_initialized = 0`
- `tunables.admin_group = 0` (wheel) while the user's primary gid is 20 (staff),
  so macFUSE denied every mount
- `/tmp` being a symlink to `/private/tmp`

A `devfs` mount succeeded from the same process throughout, so generic mount
permission was never in question.

## Decision

**Build against FUSE-T on macOS, and treat the linked library as the thing that
selects the mechanism.**

FUSE-T needs no kernel extension (it serves loopback NFS) and **exports the same
libfuse2 entry points `fuser` calls** — `_fuse_mount`, `_fuse_new_compat25`,
`_fuse_loop`, `_fuse_main_real`. So it is a drop-in at the linker and requires no
source change anywhere in this crate.

`fuser`'s macOS branch probes `pkg-config fuse` and links whatever it finds, so
the entire change is a shim that resolves that name to FUSE-T:

```bash
PKG_CONFIG_PATH="$PWD/packaging/fuse-t" \
RUSTFLAGS="-C link-arg=-Wl,-rpath,/usr/local/lib" \
cargo build --release
```

Both halves are required. **cargo forwards `-L` and `-l` from pkg-config and
drops `-Wl,-rpath`**, so without the second the binary links correctly and then
dies at startup with `dyld: Library not loaded … no LC_RPATH's found`.

`packaging/fuse-t/fuse.pc` declares `Version: 2.9.9` rather than FUSE-T's own
`1.2.7`, because `fuser` requires `atleast_version("2.6.0")`. The number
describes the **API level provided**, not the product.

## Consequences

### `--fuse-backend` is REMOVED; `--list-fuse-backends` remains

The flag could not select anything — the mechanism is fixed at link time — so
its only behaviour was to refuse. A flag named "choose the backend" that never
changes what happens is a trap: a user reaches for it precisely when a mount
fails, and it tells them no. It was unreleased (no tag contained it), so removal
cost nothing.

`--list-fuse-backends` answers the real question and now reports from LINKAGE,
not inventory: a FUSE-T-linked binary says `Kernel unavailable — this binary
links FUSE-T`, even with a healthy kext and `/dev/macfuse0` present.

The superseded design refused mismatches instead:

The mechanism is fixed at link time, so the flag cannot switch it. Before this
was enforced, `--fuse-backend kernel` on a FUSE-T build mounted through FUSE-T
and **reported success** — telling an examiner who chose a mechanism
deliberately that they got it when they did not.

`check_selectable` now compares the request against the recorded linkage and
refuses a mismatch, naming what was asked, what is linked, and the rebuild that
would provide it. `auto` is always allowed: it expresses no preference.

`fskit` and `fskit-local` are refused from **every** build, and not as a
packaging gap — FSKit is a separate Apple programming model (`FSModule`), not a
library this crate can link. Related: `--fuse-backend fskit` used to pass
`backend=fskit` as a mount option, but `mount_macfuse` accepts no `backend`
option at all; that name was inferred from a `backend=%s` format string inside
`libfuse.2.dylib` and was never user-passable.

`check_selectable` has **no catch-all arm**. Inside the defining crate every
variant is reachable, so adding a backend fails to compile until someone decides
how it is served — a `_` arm would silently refuse it instead.

### Genuine runtime selection — investigated and rejected

`fuser` 0.18 offers `macos-no-mount`, where the caller supplies the `/dev/fuse`
descriptor via `Session::from_fd` and fuser keeps the 9,649-line protocol layer.
Both libraries mention `_FUSE_COMMFD`, libfuse's socketpair + `SCM_RIGHTS`
handshake, which `nix` already wraps **safely** — so the fd could in principle be
obtained with no `unsafe`, important in a crate that is `#![forbid(unsafe_code)]`
in every module with zero exceptions.

**A spike killed it.** FUSE-T has no external mount helper to exec:

```
fuse: socketpair() failed          ← libfuse-t creates the pair itself
fuse: fork failed
/usr/local/bin/go-nfsv4            ← forks its own NFS server
```

The descriptor is created *inside* `fuse_mount()`, one end of a socketpair whose
other end feeds FUSE-T's NFS translator. There is no handshake to join from
outside. Obtaining it means calling `fuse_mount()` through FFI — the `unsafe`
the COMMFD route existed to avoid — or reimplementing FUSE-T's undocumented
internal protocol inside a forensic tool.

So runtime selection would reach **macFUSE only**: the mechanism that does not
work here. The cost is `unsafe` FFI or an undocumented dependency; the benefit
is choosing between one broken backend and nothing. Not built.

The `fuser` 0.18 upgrade is likewise unmotivated — its only payoff was
`macos-no-mount`, and 0.18 was measured failing identically to 0.16 against
macFUSE.

### Capability is detected, never declared

An earlier revision had a `fuse-t` cargo feature. It was **empty**: switching it
on changed no linkage but made the probe announce FUSE-T while macFUSE was
linked — reporting inventory as capability, the exact defect
`tests/mount_smoke.rs` exists to catch.

It is deleted. `build.rs` asks `pkg-config` what will actually be linked and
records it in `FUSE_LINKED_LIB`. **A feature is a request; the linker's input is
a fact.** Any future backend must be detected the same way.

### The mount is verified, at last

`tests/mount_smoke.rs` now executes Case A of its three-way control for the first
time in this repository's history:

```
Kernel: mounted, 2 entries match the VFS layer
FuseT:  mounted, 2 entries match the VFS layer
```

Before this, nothing here had ever proven that a mount works — the tests named
`…and_mounts_inner` exercise the VFS layer and never touch FUSE.

### Comparing a mount to the VFS layer needs the right root

`4n6mount` presents a **forensic layout** at the mount point — `ro/`, `rw/`,
`journal/`, `metadata/`, `session/`, `unallocated/` — with the image's own
filesystem under `ro/root/`. The VFS layer returns the image root. Comparing the
mount point against it compares two different things; the first version of the
smoke test did exactly that and reported a *successful* mount as a failure.

### The default build is unchanged

Without the shim the crate still builds against macFUSE, and its probe correctly
reports `FuseT unavailable … rebuild against FUSE-T to use it`. Linux is
untouched.

## The method note worth keeping

Every wrong turn here was the same error: **reading capability out of an
artifact instead of out of behaviour.** A `backend=%s` string was mistaken for a
mount option; a registered FSKit module for a routable one; a library on disk
for a linked one; `fuser`'s gated libfuse3 branch for proof FUSE-T was
unreachable — when FUSE-T's *exported symbols* said otherwise the whole time.

A 40-line FUSE program answers "is it us?" in one command, and should be the
first thing run when a mount fails. It is kept at `examples/minfuse.rs`.
