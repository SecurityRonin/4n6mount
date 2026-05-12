#![no_main]
use libfuzzer_sys::fuzz_target;
use forensic_mount::inode_map::{decode_fuse_ino, ro_ino, rw_ino, deleted_ino, journal_ino, metadata_ino};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }
    let ino = u64::from_le_bytes(data[..8].try_into().unwrap());
    let ro = ro_ino(ino);
    let rw = rw_ino(ino);
    let del = deleted_ino(ino);
    let jrn = journal_ino(ino);
    let meta = metadata_ino(ino);
    let _ = decode_fuse_ino(ro);
    let _ = decode_fuse_ino(rw);
    let _ = decode_fuse_ino(del);
    let _ = decode_fuse_ino(jrn);
    let _ = decode_fuse_ino(meta);
});
