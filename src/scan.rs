//! Scansione delle cartelle da trasferire, con le esclusioni automatiche.
//!
//! Regole:
//! - mai seguire collegamenti simbolici o junction (evita loop e doppioni);
//! - saltare i file "solo online" di OneDrive (aprirli li scaricherebbe);
//! - dentro AppData saltare cache, file temporanei, Docker, app dello Store;
//! - nella home saltare OneDrive, AppData, NTUSER e le cache dei toolchain.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use walkdir::WalkDir;

use crate::protocol::{DirEntry, FileEntry, Root};
use crate::sysinfo::KnownFolders;
use crate::util;

#[derive(Debug, Default)]
pub struct ScanResult {
    pub root: Root,
    pub base: PathBuf,
    pub files: Vec<FileEntry>,
    pub dirs: Vec<DirEntry>,
    pub bytes: u64,
    /// (percorso, motivo) degli elementi saltati o illeggibili.
    pub errors: Vec<(String, String)>,
}

impl ScanResult {
    /// Percorso assoluto sul PC vecchio del file `f` di questa scansione.
    pub fn source_path(&self, f: &FileEntry) -> PathBuf {
        if self.root == Root::Absolute {
            PathBuf::from(&f.rel)
        } else {
            self.base.join(&f.rel)
        }
    }
}

const ATTR_OFFLINE: u32 = 0x1000;
const ATTR_RECALL_ON_OPEN: u32 = 0x40000;
const ATTR_RECALL_ON_DATA_ACCESS: u32 = 0x400000;

/// Nomi di cartella (minuscoli) che sono cache, a qualunque profondità dentro AppData.
const CACHE_DIR_NAMES: &[&str] = &[
    "cache",
    "cache2",
    "code cache",
    "gpucache",
    "shadercache",
    "dawncache",
    "dawngraphitecache",
    "dawnwebgpucache",
    "cachestorage",
    "cachedfiles",
    "service worker",
    "temp",
    "tmp",
    "inetcache",
    "webcache",
    "crashdumps",
    "crashpad",
    "d3dscache",
    "squirreltemp",
];

/// Sottocartelle (relative, minuscole) di AppData\Local da saltare.
const LOCAL_SKIP: &[&str] = &[
    "temp",
    "packages",
    "docker",
    "transfermon",
    "connecteddevicesplatform",
    "d3dscache",
    "crashdumps",
    "microsoft\\windows\\explorer",
    "microsoft\\windows\\inetcache",
    "microsoft\\windows\\webcache",
    "microsoft\\windows\\caches",
    "microsoft\\windows\\wer",
    "microsoft\\windows\\notifications",
    "microsoft\\windows\\burn",
    "microsoft\\windowsapps",
    "microsoft\\onedrive",
    "nvidia\\dxcache",
    "nvidia\\glcache",
    "amd\\dxcache",
    "amd\\glcache",
];

/// Sottocartelle (relative, minuscole) di AppData\Roaming da saltare.
const ROAMING_SKIP: &[&str] = &[
    "microsoft\\windows\\recent",
    "microsoft\\windows\\recent items",
];

/// Sottocartelle (relative, minuscole) della home da saltare.
const HOME_SKIP: &[&str] = &[
    ".docker",
    ".rustup",
    ".cache",
    ".cargo\\registry",
    ".cargo\\git",
    ".nuget\\packages",
    ".gradle\\caches",
    ".android\\avd",
];

/// Junction legacy e voci di sistema al primo livello della home.
const HOME_TOP_SKIP: &[&str] = &[
    "appdata",
    "application data",
    "cookies",
    "local settings",
    "my documents",
    "nethood",
    "printhood",
    "recent",
    "sendto",
    "start menu",
    "templates",
    "intelgraphicsprofiles",
];

fn norm(p: &Path) -> String {
    p.to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_lowercase()
}

fn rel_of(base: &Path, p: &Path) -> String {
    p.strip_prefix(base)
        .map(|r| r.to_string_lossy().replace('/', "\\"))
        .unwrap_or_else(|_| p.to_string_lossy().replace('/', "\\"))
}

#[cfg(windows)]
fn file_attributes(md: &std::fs::Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt;
    md.file_attributes()
}

#[cfg(not(windows))]
fn file_attributes(_md: &std::fs::Metadata) -> u32 {
    0
}

/// File di OneDrive/Files On-Demand non scaricato: leggerlo lo scaricherebbe.
fn is_online_only(md: &std::fs::Metadata) -> bool {
    file_attributes(md) & (ATTR_OFFLINE | ATTR_RECALL_ON_OPEN | ATTR_RECALL_ON_DATA_ACCESS) != 0
}

fn keep(root: Root, base: &Path, e: &walkdir::DirEntry, known: &[String]) -> bool {
    if e.depth() == 0 {
        return true;
    }
    if e.file_type().is_symlink() {
        return false;
    }
    let name = e.file_name().to_string_lossy().to_lowercase();
    let rel = rel_of(base, e.path()).to_lowercase();
    match root {
        Root::Home => {
            if e.depth() == 1
                && (name.starts_with("onedrive")
                    || name.starts_with("ntuser.")
                    || HOME_TOP_SKIP.contains(&name.as_str())
                    || known.contains(&norm(e.path())))
            {
                return false;
            }
            !HOME_SKIP.contains(&rel.as_str())
        }
        Root::Roaming | Root::Local => {
            if e.file_type().is_dir()
                && (CACHE_DIR_NAMES.contains(&name.as_str())
                    || name.ends_with("-cache")
                    || name.ends_with("_cache")
                    || name.ends_with(" cache"))
            {
                return false;
            }
            let skip = if root == Root::Local { LOCAL_SKIP } else { ROAMING_SKIP };
            !skip.contains(&rel.as_str())
        }
        Root::Absolute => true,
        _ => {
            !(e.depth() == 1 && (name.starts_with("onedrive") || known.contains(&norm(e.path()))))
        }
    }
}

/// Scansiona `base` come radice `root`. Non apre nessun file: usa solo gli
/// attributi restituiti dall'elenco directory.
pub fn scan(root: Root, base: &Path, kf: &KnownFolders, cancel: &AtomicBool) -> ScanResult {
    let mut out = ScanResult {
        root,
        base: base.to_path_buf(),
        ..Default::default()
    };
    let known: Vec<String> = kf.known_paths().iter().map(|p| norm(p)).collect();
    let walker = WalkDir::new(base)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| keep(root, base, e, &known));
    for item in walker {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let entry = match item {
            Ok(e) => e,
            Err(err) => {
                let p = err
                    .path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| base.display().to_string());
                out.errors.push((p, err.to_string()));
                continue;
            }
        };
        let md = match entry.metadata() {
            Ok(m) => m,
            Err(err) => {
                out.errors
                    .push((entry.path().display().to_string(), err.to_string()));
                continue;
            }
        };
        if entry.depth() == 0 {
            if !md.is_dir() {
                out.errors
                    .push((base.display().to_string(), "non è una cartella".into()));
                break;
            }
            if root == Root::Absolute {
                out.dirs.push(DirEntry {
                    root,
                    rel: entry.path().to_string_lossy().replace('/', "\\"),
                });
            }
            continue;
        }
        let rel = if root == Root::Absolute {
            entry.path().to_string_lossy().replace('/', "\\")
        } else {
            rel_of(base, entry.path())
        };
        if md.is_dir() {
            out.dirs.push(DirEntry { root, rel });
        } else if md.is_file() {
            if is_online_only(&md) {
                out.errors
                    .push((rel, "file solo online (OneDrive), saltato".into()));
                continue;
            }
            let size = md.len();
            out.bytes += size;
            out.files.push(FileEntry {
                root,
                rel,
                size,
                mtime: util::unix_mtime(&md),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("transfermon-scan-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn local_skips_caches_and_temp() {
        let base = tmp("local");
        let kf = KnownFolders::under(&base);
        let local = kf.local.clone();
        fs::create_dir_all(local.join("Google\\Chrome\\User Data\\Default\\Cache")).unwrap();
        fs::create_dir_all(local.join("Temp")).unwrap();
        fs::create_dir_all(local.join("MyApp\\data")).unwrap();
        fs::write(local.join("Google\\Chrome\\User Data\\Default\\Cache\\x"), b"1").unwrap();
        fs::write(local.join("Google\\Chrome\\User Data\\Default\\Preferences"), b"22").unwrap();
        fs::write(local.join("Temp\\t.tmp"), b"333").unwrap();
        fs::write(local.join("MyApp\\data\\db.sqlite"), b"4444").unwrap();
        let r = scan(Root::Local, &local, &kf, &AtomicBool::new(false));
        let rels: Vec<&str> = r.files.iter().map(|f| f.rel.as_str()).collect();
        assert!(rels.contains(&"Google\\Chrome\\User Data\\Default\\Preferences"));
        assert!(rels.contains(&"MyApp\\data\\db.sqlite"));
        assert_eq!(rels.len(), 2, "{rels:?}");
        assert_eq!(r.bytes, 6);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn home_skips_known_folders_and_onedrive() {
        let base = tmp("home");
        let kf = KnownFolders::under(&base);
        fs::create_dir_all(&kf.documents).unwrap();
        fs::create_dir_all(kf.home.join("AppData\\Roaming")).unwrap();
        fs::create_dir_all(kf.home.join("OneDrive - Azienda")).unwrap();
        fs::create_dir_all(kf.home.join(".ssh")).unwrap();
        fs::write(kf.documents.join("doc.txt"), b"doc").unwrap();
        fs::write(kf.home.join("AppData\\Roaming\\x"), b"x").unwrap();
        fs::write(kf.home.join("OneDrive - Azienda\\y"), b"y").unwrap();
        fs::write(kf.home.join(".ssh\\id_ed25519"), b"key").unwrap();
        fs::write(kf.home.join("NTUSER.DAT"), b"reg").unwrap();
        let r = scan(Root::Home, &kf.home, &kf, &AtomicBool::new(false));
        let rels: Vec<&str> = r.files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, vec![".ssh\\id_ed25519"], "{rels:?}");
        let _ = fs::remove_dir_all(&base);
    }
}
