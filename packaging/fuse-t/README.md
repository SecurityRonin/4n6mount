# Building 4n6mount against FUSE-T

`4n6mount` links `libfuse` through the `fuser` crate. On macOS, `fuser` probes
`pkg-config fuse` and takes whatever it finds — normally macFUSE.

**On macOS 27 that does not work.** macFUSE 5.4.0's libfuse2 layer cannot mount:
verified against four independent clients, including libewf's own `ewfmount`,
which fails with `volicon: missing 'iconpath' option`. It is not a permission,
a kext approval or a staging problem — all of those were fixed first and none
of them was the cause.

FUSE-T needs no kernel extension (it serves loopback NFS) and exports the same
libfuse2 API `fuser` calls, so it is a drop-in at the linker.

## Build

```bash
brew install --cask fuse-t

PKG_CONFIG_PATH="$PWD/packaging/fuse-t" \
RUSTFLAGS="-C link-arg=-Wl,-rpath,/usr/local/lib" \
cargo build --release
```

Both parts are required:

- `PKG_CONFIG_PATH` makes `fuser` resolve `fuse` to FUSE-T.
- `RUSTFLAGS` adds the rpath. **cargo forwards `-L` and `-l` from pkg-config but
  drops `-Wl,-rpath`**, so without this the binary links correctly and then dies
  at startup with `dyld: Library not loaded ... no LC_RPATH's found`.

## Verify

```bash
otool -L target/release/4n6mount | grep fuse     # @rpath/libfuse-t.dylib
./target/release/4n6mount --list-fuse-backends   # FuseT available
cargo test --test mount_smoke -- --nocapture     # mounts and matches the VFS layer
```

A FUSE-T mount appears as NFS, which is expected:

```
fuse-t:/exfat-mnt on /Users/you/exfat-mnt (nfs, nodev, nosuid, read-only, ...)
```

`read-only` is the important word for evidence work and is set by 4n6mount, not
by FUSE-T.
