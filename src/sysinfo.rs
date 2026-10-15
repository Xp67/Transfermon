//! Informazioni sulla macchina locale: cartelle note, nome, utente, indirizzi IP.

use std::fs::OpenOptions;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use crate::protocol::Root;
use crate::util;

/// Le cartelle note del profilo utente corrente.
#[derive(Clone, Debug)]
pub struct KnownFolders {
    pub home: PathBuf,
    pub desktop: PathBuf,
    pub documents: PathBuf,
    pub downloads: PathBuf,
    pub pictures: PathBuf,
    pub music: PathBuf,
    pub videos: PathBuf,
    pub roaming: PathBuf,
    pub local: PathBuf,
}

impl KnownFolders {
    /// Rileva le cartelle note con le API di Windows (gestisce anche i casi in
    /// cui Documenti o Desktop sono spostati dentro OneDrive).
    pub fn detect() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from(r"C:\Users\Default"));
        let or = |o: Option<PathBuf>, name: &str| o.unwrap_or_else(|| home.join(name));
        KnownFolders {
            desktop: or(dirs::desktop_dir(), "Desktop"),
            documents: or(dirs::document_dir(), "Documents"),
            downloads: or(dirs::download_dir(), "Downloads"),
            pictures: or(dirs::picture_dir(), "Pictures"),
            music: or(dirs::audio_dir(), "Music"),
            videos: or(dirs::video_dir(), "Videos"),
            roaming: or(dirs::data_dir(), r"AppData\Roaming"),
            local: or(dirs::data_local_dir(), r"AppData\Local"),
            home,
        }
    }

    /// Cartelle fittizie sotto `base`, per i test.
    pub fn under(base: &Path) -> Self {
        let home = base.join("home");
        KnownFolders {
            desktop: home.join("Desktop"),
            documents: home.join("Documents"),
            downloads: home.join("Downloads"),
            pictures: home.join("Pictures"),
            music: home.join("Music"),
            videos: home.join("Videos"),
            roaming: home.join("AppData").join("Roaming"),
            local: home.join("AppData").join("Local"),
            home,
        }
    }

    pub fn path_for(&self, root: Root) -> Option<&Path> {
        Some(match root {
            Root::Desktop => &self.desktop,
            Root::Documents => &self.documents,
            Root::Downloads => &self.downloads,
            Root::Pictures => &self.pictures,
            Root::Music => &self.music,
            Root::Videos => &self.videos,
            Root::Home => &self.home,
            Root::Roaming => &self.roaming,
            Root::Local => &self.local,
            Root::Absolute => return None,
        })
    }

    /// Tutte le cartelle note tranne la home (servono per escluderle dalla
    /// scansione della home stessa).
    pub fn known_paths(&self) -> Vec<&Path> {
        vec![
            &self.desktop,
            &self.documents,
            &self.downloads,
            &self.pictures,
            &self.music,
            &self.videos,
            &self.roaming,
            &self.local,
        ]
    }
}

pub fn computer_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "PC".to_string())
}

pub fn user_name() -> String {
    std::env::var("USERNAME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "utente".to_string())
}

#[derive(Clone, Debug)]
pub struct LocalIp {
    pub iface: String,
    pub ip: Ipv4Addr,
    pub broadcast: Option<Ipv4Addr>,
}

/// Indirizzi IPv4 delle interfacce attive (escluse loopback e link-local).
pub fn local_ipv4s() -> Vec<LocalIp> {
    let mut out = Vec::new();
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            if iface.is_loopback() {
                continue;
            }
            if let if_addrs::IfAddr::V4(v4) = &iface.addr {
                if v4.ip.is_link_local() {
                    continue;
                }
                out.push(LocalIp {
                    iface: iface.name.clone(),
                    ip: v4.ip,
                    broadcast: v4.broadcast,
                });
            }
        }
    }
    out
}

/// `%LOCALAPPDATA%\Transfermon`: log, export winget, elenchi programmi.
pub fn app_dir() -> PathBuf {
    let base = dirs::data_local_dir().unwrap_or_else(std::env::temp_dir);
    let dir = base.join("Transfermon");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

pub fn log_file_path() -> PathBuf {
    app_dir().join("transfermon.log")
}

/// Scrive i panic nel file di log (l'eseguibile release non ha console).
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("[{}] PANIC: {info}\n", util::now_unix());
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(log_file_path()) {
            let _ = f.write_all(msg.as_bytes());
        }
        eprintln!("{msg}");
    }));
}
