//! Smallest possible FUSE filesystem, to isolate our code from the stack.
//!
//! If this mounts and 4n6mount does not, the fault is ours. If neither mounts,
//! it is macFUSE or `fuser`, and no amount of work in this repo will fix it.
use fuser::{FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyDirectory, Request};
use std::time::{Duration, UNIX_EPOCH};

struct Min;

impl Filesystem for Min {
    fn getattr(&mut self, _r: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        if ino == 1 {
            let a = FileAttr {
                ino: 1,
                size: 0,
                blocks: 0,
                atime: UNIX_EPOCH,
                mtime: UNIX_EPOCH,
                ctime: UNIX_EPOCH,
                crtime: UNIX_EPOCH,
                kind: FileType::Directory,
                perm: 0o755,
                nlink: 2,
                uid: 501,
                gid: 20,
                rdev: 0,
                blksize: 512,
                flags: 0,
            };
            reply.attr(&Duration::from_secs(1), &a);
        } else {
            reply.error(libc::ENOENT);
        }
    }
    fn readdir(&mut self, _r: &Request, ino: u64, _fh: u64, off: i64, mut reply: ReplyDirectory) {
        if ino != 1 {
            reply.error(libc::ENOENT);
            return;
        }
        if off == 0 {
            let _ = reply.add(1, 1, FileType::Directory, ".");
            let _ = reply.add(1, 2, FileType::Directory, "..");
            let _ = reply.add(1, 3, FileType::RegularFile, "PROOF");
        }
        reply.ok();
    }
}

fn main() {
    let mp = std::env::args()
        .nth(1)
        .expect("usage: minfuse <mountpoint>");
    match fuser::mount2(Min, &mp, &[MountOption::FSName("minfuse".into())]) {
        Ok(()) => eprintln!("minfuse: clean exit"),
        Err(e) => eprintln!(
            "minfuse: MOUNT FAILED: {e} (raw_os_error={:?})",
            e.raw_os_error()
        ),
    }
}
