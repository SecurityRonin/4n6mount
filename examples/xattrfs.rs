//! A minimal FUSE filesystem that SERVES an extended attribute, to settle
//! whether FUSE-T's NFS round trip carries xattrs to the client.
//!
//! # Result (macOS 27.0, FUSE-T 1.2.7)
//!
//! It does not, and the transport is why:
//!
//! ```text
//! CALLBACK getattr(ino=1)  x37   <- control: the filesystem IS driven
//! CALLBACK listxattr       x0
//! CALLBACK getxattr        x0
//! ```
//!
//! The client's `xattr -p` never reaches this filesystem. `-o native_xattr`
//! and `-o auto_xattr` change nothing (111 getattr, still zero xattr calls).
//!
//! Usage: `xattrfs <mountpoint> [extra -o options...]`, then in another shell
//! `xattr -l <mountpoint>/probe.txt`. Watch this process's stderr for the
//! callbacks. Kill and `umount` when done.
//!
//! Isolates FUSE-T from this project's plumbing: one file, one attribute,
//! hard-coded. If `xattr -l` on the mount shows it, the transport carries
//! attributes and any loss is ours. If it does not, the loss is the transport's
//! and no amount of reader work will recover it.

use std::ffi::OsStr;
use std::time::{Duration, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyDirectory, ReplyEntry, ReplyXattr,
    Request,
};

const TTL: Duration = Duration::from_secs(1);
const FILE_INO: u64 = 2;
const NAME: &str = "probe.txt";
const XATTR_NAME: &str = "user.forensicprobe";
const XATTR_VALUE: &[u8] = b"survived-the-nfs-round-trip";

fn attr(ino: u64, kind: FileType) -> FileAttr {
    FileAttr {
        ino,
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind,
        perm: if kind == FileType::Directory {
            0o755
        } else {
            0o644
        },
        nlink: 1,
        uid: 501,
        gid: 20,
        rdev: 0,
        blksize: 512,
        flags: 0,
    }
}

struct XattrFs;

impl Filesystem for XattrFs {
    fn lookup(&mut self, _r: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == 1 && name.to_str() == Some(NAME) {
            reply.entry(&TTL, &attr(FILE_INO, FileType::RegularFile), 0);
        } else {
            reply.error(libc::ENOENT);
        }
    }

    fn getattr(&mut self, _r: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        eprintln!("CALLBACK getattr(ino={ino})");
        match ino {
            1 => reply.attr(&TTL, &attr(1, FileType::Directory)),
            FILE_INO => reply.attr(&TTL, &attr(FILE_INO, FileType::RegularFile)),
            _ => reply.error(libc::ENOENT),
        }
    }

    fn readdir(&mut self, _r: &Request, ino: u64, _fh: u64, off: i64, mut reply: ReplyDirectory) {
        if ino != 1 {
            reply.error(libc::ENOTDIR);
            return;
        }
        let entries = [
            (1, FileType::Directory, "."),
            (1, FileType::Directory, ".."),
            (FILE_INO, FileType::RegularFile, NAME),
        ];
        for (i, (ino, kind, name)) in entries.iter().enumerate().skip(off as usize) {
            if reply.add(*ino, (i + 1) as i64, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    /// The whole point: report exactly one attribute name.
    fn listxattr(&mut self, _r: &Request, ino: u64, size: u32, reply: ReplyXattr) {
        eprintln!("CALLBACK listxattr(ino={ino}, size={size})");
        if ino != FILE_INO {
            reply.error(libc::ENOTSUP);
            return;
        }
        // The list is NUL-terminated names, concatenated.
        let mut buf = Vec::new();
        buf.extend_from_slice(XATTR_NAME.as_bytes());
        buf.push(0);
        if size == 0 {
            reply.size(buf.len() as u32);
        } else if size as usize >= buf.len() {
            reply.data(&buf);
        } else {
            reply.error(libc::ERANGE);
        }
    }

    fn getxattr(&mut self, _r: &Request, ino: u64, name: &OsStr, size: u32, reply: ReplyXattr) {
        eprintln!(
            "CALLBACK getxattr(ino={ino}, name={}, size={size})",
            name.to_string_lossy()
        );
        if ino != FILE_INO || name.to_str() != Some(XATTR_NAME) {
            reply.error(libc::ENOATTR);
            return;
        }
        if size == 0 {
            reply.size(XATTR_VALUE.len() as u32);
        } else if size as usize >= XATTR_VALUE.len() {
            reply.data(XATTR_VALUE);
        } else {
            reply.error(libc::ERANGE);
        }
    }
}

fn main() {
    let Some(mp) = std::env::args().nth(1) else {
        eprintln!("usage: xattrfs <mountpoint> [extra -o options...]");
        std::process::exit(2);
    };
    let mut opts = vec![MountOption::RO, MountOption::FSName("xattrprobe".into())];
    // Probe whether FUSE-T can be TOLD to carry attributes.
    for extra in std::env::args().skip(2) {
        opts.push(MountOption::CUSTOM(extra));
    }
    if let Err(e) = fuser::mount2(XattrFs, mp, &opts) {
        eprintln!("mount failed: {e}");
        std::process::exit(1);
    }
}
