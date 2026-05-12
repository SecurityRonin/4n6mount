#![forbid(unsafe_code)]

use crate::session::Session;
use crate::ForensicFs;
use crate::MountOptions;
use std::io;
use std::path::Path;

/// Mount a `ForensicFs` via `WinFSP` on Windows.
///
/// This is a stub -- `WinFSP` support will be implemented when the
/// `winfsp-wrs` crate is integrated.  Until then it unconditionally
/// returns `io::ErrorKind::Unsupported`.
pub fn mount_windows(
    _fs: Box<dyn ForensicFs + Send>,
    _mountpoint: &Path,
    _session: Option<Session>,
    _options: &MountOptions,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows FUSE (WinFSP) support not yet implemented",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    // Minimal mock so we can call mount_windows without a real fs.
    struct StubFs;

    impl crate::ForensicFs for StubFs {
        fn root_ino(&self) -> u64 {
            2
        }
        fn read_dir(&mut self, _ino: u64) -> FsResult<Vec<FsDirEntry>> {
            Ok(vec![])
        }
        fn lookup(&mut self, _parent: u64, _name: &[u8]) -> FsResult<Option<u64>> {
            Ok(None)
        }
        fn metadata(&mut self, _ino: u64) -> FsResult<FsMetadata> {
            Err(FsError::NotFound("stub".into()))
        }
        fn read_file(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
            Err(FsError::NotFound("stub".into()))
        }
        fn read_file_range(&mut self, _ino: u64, _off: u64, _len: u64) -> FsResult<Vec<u8>> {
            Err(FsError::NotFound("stub".into()))
        }
        fn read_link(&mut self, _ino: u64) -> FsResult<Vec<u8>> {
            Err(FsError::NotFound("stub".into()))
        }
    }

    #[test]
    fn windows_mount_returns_unsupported() {
        let fs: Box<dyn ForensicFs + Send> = Box::new(StubFs);
        let opts = MountOptions::default();
        let result = mount_windows(fs, Path::new("/mnt"), None, &opts);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
        assert!(err.to_string().contains("WinFSP"));
    }
}
