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


## Addendum: FSKit, assessed but not built

FSKit is Apple's kext-free filesystem framework and is genuinely better than
FUSE-T on the axes that matter to a forensic reader:

| | FUSE-T | FSKit |
|---|---|---|
| Path to the kernel | loopback **NFS** | native VFS |
| Vendor | third party | Apple, first-party |
| Metadata fidelity | NFS's attribute model | native |
| macOS majors | fine today | the supported path |

The fidelity row is the real argument. A forensic tool presents timestamps,
ownership and extended attributes *as evidence*, and NFS is a lossy intermediary
for exactly those — see the measured losses below.

**It is still the wrong shape for this project.** Evidence from this session:
macFUSE's FSKit support is two `.appex` bundles inside `macfuse.app`, registered
with `pluginkit` and enabled by the user in System Settings. So FSKit means a
Swift/ObjC app extension, an app bundle, code signing, notarization and a user
toggle — against a tool that is a single static binary installed with
`cargo install` or `brew install`. That is the same objection
[ADR-0014](../../../../docs/decisions/0014-fleet-gui-standard-egui.md) raises
against Tauri, plus a second implementation in another language behind an FFI
boundary, and macOS 15.4+ only.

**Revisit when** a wrong timestamp or a dropped attribute reaches a report. That
turns FSKit from an improvement into a correctness requirement, which is a
different decision.

## Addendum: what the NFS round trip actually loses

`tests/nfs_semantics.rs` compares every entry as the image states it against the
same entry `stat`ed through the mount, across all three committed filesystem
images. Measured on macOS 27 with FUSE-T, 10 entries:

```
disagreements by field: {"uid": 3, "gid": 3, "present": 1}

  hello.txt     uid    — image 99, mounted 501
  hello.txt     gid    — image 99, mounted 20
  ...
  "HFS+ Private Data"  present — image yes, mounted MISSING
```

**The first version of this section blamed NFS for all of it, and was wrong.**
It also listed `atime: 4` — pre-1970 timestamps rendered as 1970-01-01. That was
**our** defect, not the transport's:

```rust
if t.seconds >= 0 { UNIX_EPOCH + .. } else { UNIX_EPOCH }   // fusefs::ts_to_systime
```

`-2082844800` is 1904-01-01, the HFS+ "never accessed" marker, and flattening it
turned an absence into a date an examiner could put in a report. The excuse that
the wire format cannot carry a negative time is false: `fuse_attr.atime` is an
**`i64`** and fuser's `time_from_system_time` has an explicit before-epoch
branch. Two existing unit tests had *asserted* the clamp with no rationale.
Fixed; all four `atime` disagreements are gone.

The lesson is the session's recurring one: a measured discrepancy was attributed
to the component I expected to be at fault, without checking our own conversion
first.

What remains, and what is genuinely below us:

- **Ownership is replaced with the mounting user's.** uid/gid 99 become 501/20.
  Our layer passes `uid: meta.uid` through correctly, so this is the NFS
  transport. An examiner reading ownership off the mount reads their own account.
- **An entry present in the image is missing.** `HFS+ Private Data`, a
  filesystem-internal directory. Whether to hide it is arguable; doing so
  *silently* is not.

**Extended attributes are not carried at all, and NFS IS why.**

*(Corrected 2026-09-19. This section previously read "and NFS is not why",
blaming the gap entirely on unplumbed readers. That was wrong, and it was
asserted without testing the transport — exactly the reading-capability-out-of-an-artifact
error this ADR's method note warns about.)*

FUSE-T **never issues xattr operations to the filesystem at all**. Measured with
`examples/xattrfs.rs`, a minimal FUSE filesystem that serves one hard-coded
attribute, mounted through FUSE-T:

```text
CALLBACK getattr(ino=1)      x37     <- the filesystem IS being driven
CALLBACK listxattr           x0
CALLBACK getxattr            x0
$ xattr -p user.forensicprobe /mnt/probe.txt
xattr: No such xattr: user.forensicprobe
```

The control is what makes this conclusive: 37 `getattr` calls prove the mount
works and the callbacks are wired, while the xattr callbacks are never invoked.
The client's request never reaches the filesystem, so no amount of reader or
plumbing work can surface it.

Re-tested with `-o native_xattr` (and `auto_xattr`, names the dylib accepts):
111 `getattr` calls, still **zero** xattr callbacks. It is not a missing option.

**Consequence: this ADR's own revisit condition is now met.** It said "revisit
when a wrong timestamp or a dropped attribute reaches a report — that turns
FSKit from an improvement into a correctness requirement". A dropped attribute
is now measured as *structurally unavailable* on FUSE-T, not merely absent
pending work.

So the position is:

| | |
|---|---|
| **programmatic / VFS access** | attributes ARE available — `forensic-vfs` models them as streams and the readers decode them (`apfs-core` Tier-1 validated) |
| **through a FUSE-T mount** | attributes are UNREACHABLE, permanently, by the transport |

Mount-based examination on macOS therefore cannot see extended attributes until
either macFUSE's libfuse2 layer works again or FSKit is built. Work that needs
them — quarantine flags, Finder metadata, decmpfs — must go through the library
API rather than the mount.

**Symlinks are wired** (`readlink` → `read_link`), though not yet covered by a
differential test.

File **contents** are byte-exact (6 files compared).

The test **pins this exact shape** rather than committing red or asserting a
fidelity we do not have. It stays green while the limitation is unchanged and
goes red the moment it moves in either direction — a FUSE-T release that
preserved ownership would fail here, and that failure is the news. A permanently
red check trains readers to ignore it; a green one here would be a false claim.

## Addendum: FSKit scoped (2026-09-20) — it IS the fix, and it is a build

Scoped after FUSE-T was measured dropping extended attributes, which met this
ADR's own revisit condition. Three questions, answered in order of what would
kill the route fastest.

### 1. Can FSKit carry what FUSE-T drops? YES — checked before costing anything

The gating question, asked first precisely because assuming it is the mistake
this ADR already records. Read from the macOS 27.0 SDK
(`FSKit.framework/Versions/A/Headers`), not from memory:

| loss | FSKit API |
|---|---|
| extended attributes | `FSVolumeXattrHandler` / `FSVolumeXattrOperations` — `getXattrNamed` is **`@required`**, plus `listXattrsOfItem`, `setXattr`, `maximumXattrSize` |
| ownership | `FSItemAttributeUID`, `FSItemAttributeGID` |

So FSKit is a genuine **fix**, not another mitigation — unlike FUSE-T, where the
transport never issues the request at all.

### 2. Can we get there via FUSE-T's own FSKit module? NO

FUSE-T ships one — `org.fuset.fskit-srv.module(0.1.3)` at
`/Applications/fuse-t.app/Contents/Extensions/FskitSrvModule.appex`, registered
under `com.apple.fskit.fsmodule`, and its binary mentions xattr 25 times. That
would have been a mount option instead of a build, so it was worth testing.

It is not reachable from what we link:

```text
$ strings /usr/local/lib/libfuse-t.dylib | grep -ci fskit      -> 0
$ strings /usr/local/lib/libfuse-t.dylib | grep -ci appex      -> 0
  control: grep -c go-nfsv4 -> 1, grep -ci backend -> 2   (the instrument works)
```

`-o backend=fskit` fails to mount at all; `-o backend=local` mounts and still
produces **0** xattr callbacks (32 getattr). The FSKit module is a separate
product path at version 0.1.3 while the dylib is 1.2.7 — an early, parallel
effort, not a switch on the libfuse API.

**Then the extension was actually ENABLED, and it still changed nothing.** The
inference above is from symbols, and this ADR already records one case of
reading capability out of an artifact and being wrong, so it was tested rather
than trusted. `fuse-t.app` (bundle id `org.fuset.fskit-srv`) is the FSKit host
app; its window is a status monitor that deep-links to System Settings. The
toggle would not take from the UI, so it was set with the documented CLI:

```text
$ pluginkit -e use -i org.fuset.fskit-srv.module
$ pluginkit -m -p com.apple.fskit.fsmodule -A | grep fuset
+····org.fuset.fskit-srv.module(0.1.3)          <- enabled, was blank
```

Re-running `examples/xattrfs.rs` with the extension enabled:

```text
getattr   29      <- control: the filesystem is still driven
listxattr  0
getxattr   0      <- unchanged
```

Nothing to rule out on the extension's own health either: signature valid,
notarized Developer ID, `com.apple.developer.fskit.fsmodule` entitlement
present, provisioning profile good to 2044, `LSMinimumSystemVersion` 26.0 on a
27.0 host. It is enabled and healthy and our mounts do not route through it,
because `fuser` links `libfuse-t.dylib` and that library has no path to it.

### 3. What does building our own cost? The packaging objection STANDS

Verified, not inherited:

- **An `.appex` inside an app bundle.** Every real module on this machine is one
  — Apple's `com.apple.fskit.{exfat,msdos,ftp}.appex` and FUSE-T's own. The
  extension point is `com.apple.fskit.fsmodule`.
- **macOS 15.4+** (`API_AVAILABLE(macos(15.4))`, with newer members at 26.0,
  26.4, 27.0).
- **Swift/ObjC**, so a Rust reader needs an FFI bridge or a Swift shim — a
  second implementation language across a boundary.
- **Code signing, notarization, and a user toggle** in System Settings.

Against a tool that is one static binary installed with `cargo install` or
`brew install`. That is the same objection
[ADR-0014](../../../../docs/decisions/0014-fleet-gui-standard-egui.md) raises
against Tauri.

### Position

**Not built, and the rejection is now narrower than before.** Previously FSKit
was declined as an improvement not worth the packaging. It is now the only route
to a mount that does not drop evidence on macOS, so the trade is real capability
against real packaging cost — not polish against cost.

Until it is built, the honest arrangement is what ships today:

- the mount **declares** its losses, in the terminal and in
  `metadata/mount-fidelity.json` (see `tests/mount_fidelity.rs`)
- the **library API** (`forensic-vfs data_streams`) is the lossless route, and
  is where the nine readers' extended-attribute work lands

**Build it when** mount-based examination becomes the primary workflow for
macOS evidence, or when an examiner needs attributes visible in a file browser
rather than through the API. Both are product decisions, not engineering ones.

