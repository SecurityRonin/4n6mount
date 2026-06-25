#![forbid(unsafe_code)]

//! Synthetic inode registry for the memory VFS.
//!
//! The memory mount has no on-disk inodes, so each path node is assigned a
//! synthetic inode here. Phase 1 holds only the static top-level directories;
//! later phases grow the registry lazily (the `proc/<pid>` list materializes on
//! first `read_dir(proc)`, forensic findings on first access, etc.) and add
//! file artifacts whose bytes are rendered on `read_file`.

use std::collections::HashMap;

/// Root inode of the memory VFS (mirrors the disk providers' root = 2).
pub const ROOT_INO: u64 = 2;

/// What a synthetic inode represents. Directories plus the lazily-rendered file
/// artifacts; later phases add the `proc/`, `forensic/`, and `mem/` artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Artifact {
    Dir,
    /// `sys/os-info.txt` — the analysis profile, rendered from `AnalysisContext`.
    SysOsInfo,
}

/// One node in the synthetic tree.
pub struct Node {
    pub name: Vec<u8>,
    pub artifact: Artifact,
    pub children: Vec<u64>,
}

impl Node {
    fn dir(name: &str) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            artifact: Artifact::Dir,
            children: vec![],
        }
    }

    pub fn is_dir(&self) -> bool {
        matches!(self.artifact, Artifact::Dir)
    }
}

/// The inode → node map plus a (parent, name) → inode index for lookups.
pub struct Registry {
    nodes: HashMap<u64, Node>,
    index: HashMap<(u64, Vec<u8>), u64>,
}

impl Registry {
    /// Build the static top-level skeleton: the root holding `sys/`, `proc/`,
    /// `forensic/`, and `mem/`. Later phases grow these subtrees lazily.
    pub fn skeleton() -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(
            ROOT_INO,
            Node {
                name: b"/".to_vec(),
                artifact: Artifact::Dir,
                children: vec![],
            },
        );
        let mut registry = Self {
            nodes,
            index: HashMap::new(),
        };
        for (ino, name) in [(3, "sys"), (4, "proc"), (5, "forensic"), (6, "mem")] {
            registry.add_dir(ROOT_INO, ino, name);
        }
        // sys/os-info.txt — the first lazily-rendered artifact.
        registry.add_file(3, 7, "os-info.txt", Artifact::SysOsInfo);
        registry
    }

    /// Add a child directory under `parent`.
    fn add_dir(&mut self, parent: u64, ino: u64, name: &str) {
        self.add_node(parent, ino, Node::dir(name));
    }

    /// Add a child file `artifact` named `name` under `parent`.
    fn add_file(&mut self, parent: u64, ino: u64, name: &str, artifact: Artifact) {
        self.add_node(
            parent,
            ino,
            Node {
                name: name.as_bytes().to_vec(),
                artifact,
                children: vec![],
            },
        );
    }

    fn add_node(&mut self, parent: u64, ino: u64, node: Node) {
        let key = (parent, node.name.clone());
        self.nodes.insert(ino, node);
        self.index.insert(key, ino);
        if let Some(p) = self.nodes.get_mut(&parent) {
            p.children.push(ino);
        }
    }

    pub fn node(&self, ino: u64) -> Option<&Node> {
        self.nodes.get(&ino)
    }

    pub fn lookup(&self, parent: u64, name: &[u8]) -> Option<u64> {
        self.index.get(&(parent, name.to_vec())).copied()
    }
}
