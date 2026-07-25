# Test fixtures

| File | Provenance | Contents | Used by |
|---|---|---|---|
| `hello.zip` | SYNTHETIC — minted with `zip -qr hello.zip .` over a tree of `hello.txt` (`hello from archive\n`) + `sub/deep.txt` (`deep content\n`) | a Zip archive with a root file and one nested dir | `tests/mount_archive_logical.rs` — archive-mount regression guard |

Classification: SYNTHETIC. No redistribution concerns (self-authored).
