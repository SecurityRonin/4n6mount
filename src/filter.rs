#![allow(dead_code)]

use md5::{Digest, Md5};
use std::collections::HashSet;
use std::io;
use std::path::Path;

/// Compute MD5 hash of data, returning lowercase hex string.
pub fn compute_md5(data: &[u8]) -> String {
    let mut hasher = Md5::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// A known-good hash database for filtering.
pub trait FilterDb {
    /// Check if an MD5 hash exists in this database.
    fn contains_md5(&self, md5: &str) -> bool;
}

/// Plain text file with one MD5 hash per line.
pub struct CustomDb {
    hashes: HashSet<String>,
}

impl CustomDb {
    pub fn load(path: &Path) -> io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let hashes: HashSet<String> = content
            .lines()
            .map(|line| line.trim().to_lowercase())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .collect();
        Ok(Self { hashes })
    }
}

impl FilterDb for CustomDb {
    fn contains_md5(&self, md5: &str) -> bool {
        self.hashes.contains(&md5.to_lowercase())
    }
}

/// `HashKeeper` format: lines of "`file_id,directory_id,file_name,filesize,md5`"
/// or simpler format with just MD5 + filename separated by comma/tab.
pub struct HashKeeperDb {
    hashes: HashSet<String>,
}

impl HashKeeperDb {
    pub fn load(path: &Path) -> io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut hashes = HashSet::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('%') {
                continue;
            }
            // Try to extract MD5 — it's 32 hex chars
            // HashKeeper format varies, but MD5 is usually the last or a specific column
            for field in line.split([',', '\t']) {
                let field = field.trim().to_lowercase();
                if field.len() == 32 && field.chars().all(|c| c.is_ascii_hexdigit()) {
                    hashes.insert(field);
                    break;
                }
            }
        }
        Ok(Self { hashes })
    }
}

impl FilterDb for HashKeeperDb {
    fn contains_md5(&self, md5: &str) -> bool {
        self.hashes.contains(&md5.to_lowercase())
    }
}

/// NSRL `RDSv3` `SQLite` database.
pub struct NsrlDb {
    hashes: HashSet<String>,
}

impl NsrlDb {
    /// Load NSRL database by reading all MD5 hashes into memory.
    /// For `RDSv3` `SQLite`: SELECT md5 FROM FILE (or similar table).
    /// Falls back to treating the file as a plain text hash list.
    pub fn load(path: &Path) -> io::Result<Self> {
        // Try SQLite first
        if let Ok(db) = Self::load_sqlite(path) {
            return Ok(db);
        }
        // Fall back to text format
        let custom = CustomDb::load(path)?;
        Ok(Self {
            hashes: custom.hashes,
        })
    }

    fn load_sqlite(path: &Path) -> io::Result<Self> {
        let conn =
            rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(io::Error::other)?;

        let mut hashes = HashSet::new();

        // RDSv3 schema: FILE table has md5 column
        // Try common table/column names
        for query in &[
            "SELECT md5 FROM FILE",
            "SELECT md5 FROM file",
            "SELECT MD5 FROM FILE",
            "SELECT hash FROM hashes WHERE type='md5'",
        ] {
            if let Ok(mut stmt) = conn.prepare(query) {
                let rows = stmt.query_map([], |row| row.get::<_, String>(0));
                if let Ok(rows) = rows {
                    for row in rows.flatten() {
                        hashes.insert(row.to_lowercase());
                    }
                    if !hashes.is_empty() {
                        break;
                    }
                }
            }
        }

        if hashes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "no MD5 hashes found in SQLite DB",
            ));
        }

        Ok(Self { hashes })
    }
}

impl FilterDb for NsrlDb {
    fn contains_md5(&self, md5: &str) -> bool {
        self.hashes.contains(&md5.to_lowercase())
    }
}

/// Aggregate filter that checks multiple databases.
pub struct FilterChain {
    dbs: Vec<Box<dyn FilterDb>>,
}

impl Default for FilterChain {
    fn default() -> Self {
        Self::new()
    }
}

impl FilterChain {
    pub fn new() -> Self {
        Self { dbs: Vec::new() }
    }

    pub fn add(&mut self, db: Box<dyn FilterDb>) {
        self.dbs.push(db);
    }

    pub fn is_empty(&self) -> bool {
        self.dbs.is_empty()
    }
}

impl FilterDb for FilterChain {
    fn contains_md5(&self, md5: &str) -> bool {
        self.dbs.iter().any(|db| db.contains_md5(md5))
    }
}

/// Cached filter results for persistence across sessions.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FilterCache {
    /// Map of ext4 inode -> (`md5_hash`, `is_known`)
    pub entries: std::collections::HashMap<u64, FilterCacheEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FilterCacheEntry {
    pub md5: String,
    pub is_known: bool,
}

impl FilterCache {
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        std::fs::write(path, json)
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json).map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn compute_md5_known_value() {
        // MD5 of empty string
        let hash = compute_md5(b"");
        assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn compute_md5_hello() {
        let hash = compute_md5(b"Hello, ext4!");
        assert_eq!(hash.len(), 32);
        // Deterministic
        assert_eq!(hash, compute_md5(b"Hello, ext4!"));
    }

    #[test]
    fn custom_db_lookup() {
        let tmp = std::env::temp_dir().join("forensic_mount_test_custom_db.txt");
        let mut f = std::fs::File::create(&tmp).unwrap();
        writeln!(f, "d41d8cd98f00b204e9800998ecf8427e").unwrap();
        writeln!(f, "# comment line").unwrap();
        writeln!(f, "098f6bcd4621d373cade4e832627b4f6").unwrap();
        drop(f);

        let db = CustomDb::load(&tmp).unwrap();
        assert!(db.contains_md5("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(db.contains_md5("098f6bcd4621d373cade4e832627b4f6"));
        assert!(!db.contains_md5("0000000000000000000000000000000"));
        // Case insensitive
        assert!(db.contains_md5("D41D8CD98F00B204E9800998ECF8427E"));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn hashkeeper_db_lookup() {
        let tmp = std::env::temp_dir().join("forensic_mount_test_hk_db.txt");
        let mut f = std::fs::File::create(&tmp).unwrap();
        writeln!(f, "% header line").unwrap();
        writeln!(f, "1,2,file.txt,100,d41d8cd98f00b204e9800998ecf8427e").unwrap();
        writeln!(f, "3,4,other.dll,200,098f6bcd4621d373cade4e832627b4f6").unwrap();
        drop(f);

        let db = HashKeeperDb::load(&tmp).unwrap();
        assert!(db.contains_md5("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(db.contains_md5("098f6bcd4621d373cade4e832627b4f6"));
        assert!(!db.contains_md5("ffffffffffffffffffffffffffffffff"));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn filter_chain_combines_dbs() {
        let tmp1 = std::env::temp_dir().join("forensic_mount_test_chain1.txt");
        let tmp2 = std::env::temp_dir().join("forensic_mount_test_chain2.txt");
        std::fs::write(&tmp1, "d41d8cd98f00b204e9800998ecf8427e\n").unwrap();
        std::fs::write(&tmp2, "098f6bcd4621d373cade4e832627b4f6\n").unwrap();

        let mut chain = FilterChain::new();
        chain.add(Box::new(CustomDb::load(&tmp1).unwrap()));
        chain.add(Box::new(CustomDb::load(&tmp2).unwrap()));

        assert!(chain.contains_md5("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(chain.contains_md5("098f6bcd4621d373cade4e832627b4f6"));
        assert!(!chain.contains_md5("0000000000000000000000000000000"));

        let _ = std::fs::remove_file(&tmp1);
        let _ = std::fs::remove_file(&tmp2);
    }

    #[test]
    fn filter_cache_roundtrip() {
        let tmp = std::env::temp_dir().join("forensic_mount_test_filter_cache.json");
        let mut cache = FilterCache::default();
        cache.entries.insert(
            12,
            FilterCacheEntry {
                md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                is_known: true,
            },
        );
        cache.save(&tmp).unwrap();

        let loaded = FilterCache::load(&tmp).unwrap();
        assert_eq!(loaded.entries.len(), 1);
        assert!(loaded.entries[&12].is_known);

        let _ = std::fs::remove_file(&tmp);
    }
}
