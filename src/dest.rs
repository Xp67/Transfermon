//! Mappatura dei percorsi ricevuti sulle cartelle del PC nuovo.

use std::path::{Component, Path, PathBuf};

use crate::protocol::Root;
use crate::sysinfo::KnownFolders;

#[derive(Clone, Debug)]
pub struct DestMap {
    kf: KnownFolders,
    /// Dove finiscono le cartelle aggiuntive di dischi che qui non esistono.
    fallback: PathBuf,
    /// Nei test tutto viene scritto sotto questa cartella.
    test_base: Option<PathBuf>,
}

impl DestMap {
    /// Cartelle reali dell'utente corrente.
    pub fn system() -> Self {
        let kf = KnownFolders::detect();
        let fallback = kf.home.join("Transfermon");
        DestMap {
            kf,
            fallback,
            test_base: None,
        }
    }

    /// Tutto sotto `base` (per i test): `base\home\...` e `base\dischi\Disco_X\...`.
    pub fn for_test(base: &Path) -> Self {
        DestMap {
            kf: KnownFolders::under(base),
            fallback: base.join("dischi"),
            test_base: Some(base.to_path_buf()),
        }
    }

    pub fn known_folders(&self) -> &KnownFolders {
        &self.kf
    }

    /// Cartella in cui atterra una radice (per le cartelle aggiuntive: il fallback).
    pub fn root_dir(&self, root: Root) -> PathBuf {
        match self.kf.path_for(root) {
            Some(p) => p.to_path_buf(),
            None => self.fallback.clone(),
        }
    }

    /// Risolve un percorso ricevuto; rifiuta i percorsi che uscirebbero dalla radice.
    pub fn resolve(&self, root: Root, rel: &str) -> Result<PathBuf, String> {
        if rel.is_empty() {
            return Err("percorso vuoto".into());
        }
        let p = Path::new(rel);
        if p.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(format!("percorso non valido (contiene ..): {rel}"));
        }
        if root == Root::Absolute {
            let b = rel.as_bytes();
            if b.len() < 3 || !b[0].is_ascii_alphabetic() || b[1] != b':' || (b[2] != b'\\' && b[2] != b'/')
            {
                return Err(format!("percorso assoluto non valido: {rel}"));
            }
            let drive = (b[0] as char).to_ascii_uppercase();
            let rest = rel[3..].trim_start_matches(['\\', '/']);
            let drive_root = format!("{drive}:\\");
            if self.test_base.is_none() && Path::new(&drive_root).is_dir() {
                return Ok(PathBuf::from(rel));
            }
            let mut out = self.fallback.join(format!("Disco_{drive}"));
            if !rest.is_empty() {
                out.push(rest);
            }
            Ok(out)
        } else {
            if rel.contains(':')
                || p.components()
                    .any(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
            {
                return Err(format!("percorso non valido: {rel}"));
            }
            Ok(self.root_dir(root).join(rel))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_and_absolute_in_known_roots() {
        let d = DestMap::for_test(Path::new(r"C:\tmp\x"));
        assert!(d.resolve(Root::Documents, r"..\..\Windows\x").is_err());
        assert!(d.resolve(Root::Documents, r"C:\Windows\x").is_err());
        assert!(d.resolve(Root::Documents, r"\Windows\x").is_err());
        assert_eq!(
            d.resolve(Root::Documents, r"a\b.txt").unwrap(),
            PathBuf::from(r"C:\tmp\x\home\Documents\a\b.txt")
        );
    }

    #[test]
    fn absolute_goes_to_disk_folder_in_tests() {
        let d = DestMap::for_test(Path::new(r"C:\tmp\x"));
        assert_eq!(
            d.resolve(Root::Absolute, r"D:\Progetti\a.txt").unwrap(),
            PathBuf::from(r"C:\tmp\x\dischi\Disco_D\Progetti\a.txt")
        );
        assert!(d.resolve(Root::Absolute, r"Progetti\a.txt").is_err());
        assert!(d.resolve(Root::Absolute, r"D:\..\a.txt").is_err());
    }
}
