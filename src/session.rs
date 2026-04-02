#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub image_path: String,
    pub image_sha256: String,
    pub created: String,
    pub examiner: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct OverlayMetadata {
    pub created: HashMap<String, OverlayEntry>,
    pub modified: HashMap<u64, String>,
    pub deleted: Vec<u64>,
    pub dirs: HashMap<String, OverlayEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OverlayEntry {
    pub parent_ino: u64,
    pub name: String,
    pub size: u64,
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Session {
    pub dir: PathBuf,
    pub metadata: SessionMetadata,
    pub overlay: OverlayMetadata,
}

impl Session {
    /// Create a new session, computing the SHA-256 of the image and persisting
    /// `session.json` plus an empty `overlay/metadata.json`.
    pub fn create(session_dir: &Path, image_path: &Path) -> io::Result<Self> {
        fs::create_dir_all(session_dir)?;
        fs::create_dir_all(session_dir.join("overlay"))?;

        let hash = compute_image_hash(image_path)?;
        let metadata = SessionMetadata {
            image_path: image_path.to_string_lossy().into_owned(),
            image_sha256: hash,
            created: chrono_now(),
            examiner: whoami(),
        };
        let overlay = OverlayMetadata::default();

        let session = Self {
            dir: session_dir.to_path_buf(),
            metadata,
            overlay,
        };
        session.save()?;
        Ok(session)
    }

    /// Resume an existing session, verifying the image hash matches.
    pub fn resume(session_dir: &Path, image_path: &Path) -> io::Result<Self> {
        let session_json = fs::read_to_string(session_dir.join("session.json"))?;
        let metadata: SessionMetadata = serde_json::from_str(&session_json)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let current_hash = compute_image_hash(image_path)?;
        if current_hash != metadata.image_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Image hash mismatch: expected {}, got {}",
                    metadata.image_sha256, current_hash
                ),
            ));
        }

        let overlay_path = session_dir.join("overlay").join("metadata.json");
        let overlay: OverlayMetadata = if overlay_path.exists() {
            let data = fs::read_to_string(&overlay_path)?;
            serde_json::from_str(&data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
        } else {
            OverlayMetadata::default()
        };

        Ok(Self {
            dir: session_dir.to_path_buf(),
            metadata,
            overlay,
        })
    }

    /// Persist session.json and overlay/metadata.json to disk.
    pub fn save(&self) -> io::Result<()> {
        let session_json = serde_json::to_string_pretty(&self.metadata)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(self.dir.join("session.json"), session_json)?;

        let overlay_dir = self.dir.join("overlay");
        fs::create_dir_all(&overlay_dir)?;
        let overlay_json = serde_json::to_string_pretty(&self.overlay)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(overlay_dir.join("metadata.json"), overlay_json)?;

        Ok(())
    }

    /// Return the filesystem path for an overlay file by id.
    pub fn overlay_file_path(&self, id: &str) -> PathBuf {
        self.dir.join("overlay").join(id)
    }

    /// Write data to an overlay file and fsync.
    pub fn write_overlay_file(&self, id: &str, data: &[u8]) -> io::Result<()> {
        let path = self.overlay_file_path(id);
        let mut f = fs::File::create(&path)?;
        f.write_all(data)?;
        f.sync_all()?;
        Ok(())
    }

    /// Read an overlay file.
    pub fn read_overlay_file(&self, id: &str) -> io::Result<Vec<u8>> {
        fs::read(self.overlay_file_path(id))
    }
}

// ---------------------------------------------------------------------------
// Free functions: export / import
// ---------------------------------------------------------------------------

/// Export a session directory as a gzipped tarball.
pub fn export_session(session_dir: &Path, output: &Path) -> io::Result<()> {
    let parent = session_dir
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "session_dir has no parent"))?;
    let dir_name = session_dir
        .file_name()
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "session_dir has no file name")
        })?;

    let status = Command::new("tar")
        .arg("-czf")
        .arg(output)
        .arg("-C")
        .arg(parent)
        .arg(dir_name)
        .status()?;

    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("tar exited with {status}"),
        ));
    }
    Ok(())
}

/// Import a gzipped tarball into a session directory.
pub fn import_session(tarball: &Path, session_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(session_dir)?;

    let status = Command::new("tar")
        .arg("-xzf")
        .arg(tarball)
        .arg("-C")
        .arg(session_dir)
        .arg("--strip-components=1")
        .status()?;

    if !status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("tar exited with {status}"),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the SHA-256 hex digest of a file.
pub fn compute_image_hash(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Current unix epoch as a string (no chrono dependency).
pub fn chrono_now() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .to_string()
}

/// Return the current user name from `$USER`.
pub fn whoami() -> String {
    std::env::var("USER").unwrap_or_else(|_| "unknown".into())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a unique temp dir for a test.
    fn tmp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("forensic_mount_test_{}_{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn create_and_resume_session() {
        let base = tmp_dir("create_resume");
        let image = base.join("fake.img");
        fs::write(&image, b"fake ext4 image data").unwrap();

        let session_dir = base.join("session");
        let session = Session::create(&session_dir, &image).unwrap();
        assert!(!session.metadata.image_sha256.is_empty());
        assert!(session_dir.join("session.json").exists());
        assert!(session_dir.join("overlay/metadata.json").exists());

        // Resume should succeed with the same image.
        let resumed = Session::resume(&session_dir, &image).unwrap();
        assert_eq!(resumed.metadata.image_sha256, session.metadata.image_sha256);

        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn resume_detects_tampered_image() {
        let base = tmp_dir("tampered");
        let image = base.join("fake.img");
        fs::write(&image, b"original content").unwrap();

        let session_dir = base.join("session");
        Session::create(&session_dir, &image).unwrap();

        // Tamper with the image.
        fs::write(&image, b"tampered content").unwrap();

        let err = Session::resume(&session_dir, &image).unwrap_err();
        assert!(
            err.to_string().contains("hash mismatch"),
            "Expected hash mismatch error, got: {err}"
        );

        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn save_persists_overlay_changes() {
        let base = tmp_dir("save_persist");
        let image = base.join("test.img");
        fs::write(&image, b"image data").unwrap();

        let session_dir = base.join("session");
        let mut session = Session::create(&session_dir, &image).unwrap();

        // Modify overlay
        session.overlay.deleted.push(42);
        session.overlay.modified.insert(100, "ino_100".to_string());
        session.save().unwrap();

        // Reload and verify
        let resumed = Session::resume(&session_dir, &image).unwrap();
        assert!(resumed.overlay.deleted.contains(&42));
        assert_eq!(resumed.overlay.modified.get(&100).unwrap(), "ino_100");

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn overlay_file_path_construction() {
        let base = tmp_dir("path_construct");
        let image = base.join("test.img");
        fs::write(&image, b"image").unwrap();

        let session_dir = base.join("session");
        let session = Session::create(&session_dir, &image).unwrap();

        let path = session.overlay_file_path("file1");
        assert!(path.ends_with("overlay/file1"));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn export_import_session_roundtrip() {
        let base = tmp_dir("export_import");
        let image = base.join("test.img");
        fs::write(&image, b"image for export").unwrap();

        // Create session with overlay data
        let session_dir = base.join("session");
        let session = Session::create(&session_dir, &image).unwrap();
        session.write_overlay_file("test_file", b"overlay data").unwrap();

        // Export
        let tarball = base.join("export.tar.gz");
        export_session(&session_dir, &tarball).unwrap();
        assert!(tarball.exists());

        // Import to new location
        let import_dir = base.join("imported");
        import_session(&tarball, &import_dir).unwrap();

        // Verify session.json exists in imported dir
        assert!(import_dir.join("session.json").exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn overlay_file_roundtrip() {
        let base = tmp_dir("overlay_rt");
        let image = base.join("fake.img");
        fs::write(&image, b"image bytes").unwrap();

        let session_dir = base.join("session");
        let session = Session::create(&session_dir, &image).unwrap();

        let payload = b"hello overlay world";
        session.write_overlay_file("test-file-1", payload).unwrap();
        let read_back = session.read_overlay_file("test-file-1").unwrap();
        assert_eq!(read_back, payload);

        fs::remove_dir_all(&base).unwrap();
    }
}
