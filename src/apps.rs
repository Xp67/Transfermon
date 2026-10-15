//! Programmi installati: lettura del registro di Windows, export/import winget.
//!
//! Windows non permette di "copiare" un programma installato da un PC a un
//! altro (registro, servizi, licenze). La strategia è:
//! 1. sul PC vecchio: elenco completo dal registro + `winget export`;
//! 2. sul PC nuovo: `winget import` reinstalla tutto ciò che winget conosce,
//!    l'elenco completo serve per installare a mano il resto;
//! 3. le impostazioni personali arrivano con la copia di AppData.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::protocol::{AppsBundle, InstalledApp};
use crate::sysinfo;
use crate::util;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Dove è stato salvato l'elenco programmi sul PC nuovo.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SavedApps {
    pub dir: PathBuf,
    pub json: Option<PathBuf>,
    pub list: PathBuf,
    pub script: Option<PathBuf>,
}

fn hide_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
    }
}

/// Programmi dal registro (HKLM 64/32 bit + HKCU), senza aggiornamenti e
/// componenti di sistema.
#[cfg(windows)]
pub fn registry_apps() -> Vec<InstalledApp> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;

    const UNINSTALL: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    const UNINSTALL_32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
    let sources = [
        (HKEY_LOCAL_MACHINE, UNINSTALL),
        (HKEY_LOCAL_MACHINE, UNINSTALL_32),
        (HKEY_CURRENT_USER, UNINSTALL),
    ];
    let mut out: Vec<InstalledApp> = Vec::new();
    for (hive, path) in sources {
        let Ok(key) = RegKey::predef(hive).open_subkey_with_flags(path, KEY_READ) else {
            continue;
        };
        for name in key.enum_keys().filter_map(|k| k.ok()) {
            let Ok(sub) = key.open_subkey_with_flags(&name, KEY_READ) else {
                continue;
            };
            let display: String = match sub.get_value("DisplayName") {
                Ok(v) => v,
                Err(_) => continue,
            };
            let display = display.trim().to_string();
            if display.is_empty() {
                continue;
            }
            let system: u32 = sub.get_value("SystemComponent").unwrap_or(0);
            if system == 1 {
                continue;
            }
            if sub.get_value::<String, _>("ParentKeyName").is_ok() {
                continue;
            }
            let release: String = sub.get_value("ReleaseType").unwrap_or_default();
            if release.contains("Update") || release.contains("Hotfix") {
                continue;
            }
            if display.starts_with("Security Update")
                || display.starts_with("Update for")
                || display.starts_with("Hotfix")
            {
                continue;
            }
            let version: String = sub.get_value("DisplayVersion").unwrap_or_default();
            let publisher: String = sub.get_value("Publisher").unwrap_or_default();
            let install_location: String = sub.get_value("InstallLocation").unwrap_or_default();
            out.push(InstalledApp {
                name: display,
                version: version.trim().to_string(),
                publisher: publisher.trim().to_string(),
                install_location: install_location.trim().to_string(),
                winget_id: None,
            });
        }
    }
    out.sort_by_key(|a| a.name.to_lowercase());
    out.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name) && a.version == b.version);
    out
}

#[cfg(not(windows))]
pub fn registry_apps() -> Vec<InstalledApp> {
    Vec::new()
}

fn winget_candidates() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("winget")];
    if let Some(local) = dirs::data_local_dir() {
        v.push(local.join(r"Microsoft\WindowsApps\winget.exe"));
    }
    v
}

fn run_winget(args: &[&str]) -> Result<std::process::Output> {
    let mut last = None;
    for exe in winget_candidates() {
        let mut cmd = Command::new(&exe);
        cmd.args(args);
        hide_window(&mut cmd);
        match cmd.output() {
            Ok(o) => return Ok(o),
            Err(e) => last = Some(e),
        }
    }
    Err(anyhow!(
        "winget non trovato ({})",
        last.map(|e| e.to_string()).unwrap_or_default()
    ))
}

/// `winget export`: restituisce il JSON prodotto e le righe di testo stampate
/// (fra cui i programmi che winget non sa reinstallare).
pub fn winget_export(log: &dyn Fn(String)) -> (Option<String>, Vec<String>) {
    let path = sysinfo::app_dir().join("winget-export.json");
    let _ = std::fs::remove_file(&path);
    let path_s = path.to_string_lossy().to_string();
    match run_winget(&[
        "export",
        "-o",
        &path_s,
        "--accept-source-agreements",
        "--disable-interactivity",
    ]) {
        Ok(out) => {
            let mut text = String::from_utf8_lossy(&out.stdout).to_string();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            let mut notes: Vec<String> = Vec::new();
            for line in text.split(['\r', '\n']) {
                let l = line.trim();
                if l.len() > 3 && !l.chars().all(|c| "-\\|/ ".contains(c)) && !notes.iter().any(|n| n == l) {
                    notes.push(l.to_string());
                }
            }
            let json = std::fs::read_to_string(&path).ok();
            if json.is_none() {
                log(format!(
                    "winget export non ha prodotto il file (codice {:?})",
                    out.status.code()
                ));
            }
            (json, notes)
        }
        Err(e) => {
            log(format!("winget non disponibile su questo PC: {e}"));
            (None, Vec::new())
        }
    }
}

fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Identificativi dei pacchetti presenti nell'export winget.
pub fn winget_ids(json: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return ids;
    };
    if let Some(sources) = v.get("Sources").and_then(|s| s.as_array()) {
        for s in sources {
            if let Some(pkgs) = s.get("Packages").and_then(|p| p.as_array()) {
                for p in pkgs {
                    if let Some(id) = p.get("PackageIdentifier").and_then(|i| i.as_str()) {
                        ids.push(id.to_string());
                    }
                }
            }
        }
    }
    ids
}

/// Associa (euristicamente) a ogni programma l'id winget che lo reinstallerà:
/// un segmento dell'id dopo l'editore (es. "Chrome" in "Google.Chrome") deve
/// comparire nel nome del programma.
pub fn attach_winget_ids(apps: &mut [InstalledApp], ids: &[String]) {
    for app in apps.iter_mut() {
        let n = normalize(&app.name);
        if n.len() < 3 {
            continue;
        }
        let mut best: Option<(usize, &String)> = None;
        for id in ids {
            let segs: Vec<&str> = id.split('.').collect();
            if segs.len() < 2 {
                continue;
            }
            for seg in &segs[1..] {
                let s = normalize(seg);
                if s.len() >= 3 && n.contains(&s) && best.map(|(l, _)| s.len() > l).unwrap_or(true) {
                    best = Some((s.len(), id));
                }
            }
        }
        app.winget_id = best.map(|(_, id)| id.clone());
    }
}

/// Raccoglie elenco programmi ed export winget sul PC vecchio.
pub fn collect(source_name: &str, log: &dyn Fn(String)) -> AppsBundle {
    let mut installed = registry_apps();
    log(format!("Programmi trovati nel registro: {}", installed.len()));
    let (json, notes) = winget_export(log);
    let ids = json.as_deref().map(winget_ids).unwrap_or_default();
    if json.is_some() {
        log(format!("winget export: {} pacchetti reinstallabili", ids.len()));
    }
    attach_winget_ids(&mut installed, &ids);
    AppsBundle {
        source_name: source_name.to_string(),
        installed,
        winget_count: ids.len(),
        winget_export_json: json,
        winget_notes: notes,
    }
}

/// Salva sul PC nuovo l'elenco programmi, l'export winget e lo script di
/// installazione in `%LOCALAPPDATA%\Transfermon\app\<pc>-<data>`.
pub fn save_bundle(bundle: &AppsBundle) -> Result<SavedApps> {
    let dir = sysinfo::app_dir().join("app").join(format!(
        "{}-{}",
        util::sanitize_filename(&bundle.source_name),
        util::now_unix()
    ));
    std::fs::create_dir_all(&dir).with_context(|| format!("creazione di {}", dir.display()))?;

    let list = dir.join("programmi-installati.txt");
    let mut text = format!(
        "Programmi installati sul PC \"{}\" ({} voci; {} reinstallabili con winget)\r\n\r\n",
        bundle.source_name,
        bundle.installed.len(),
        bundle.winget_count
    );
    text.push_str("NOME\tVERSIONE\tEDITORE\tWINGET\tCARTELLA\r\n");
    for a in &bundle.installed {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\r\n",
            a.name,
            a.version,
            a.publisher,
            a.winget_id.as_deref().unwrap_or("-"),
            a.install_location
        ));
    }
    if !bundle.winget_notes.is_empty() {
        text.push_str("\r\nMessaggi di winget durante l'export:\r\n");
        for n in &bundle.winget_notes {
            text.push_str(n);
            text.push_str("\r\n");
        }
    }
    std::fs::write(&list, text)?;

    let json = match &bundle.winget_export_json {
        Some(j) => {
            let p = dir.join("winget-export.json");
            std::fs::write(&p, j)?;
            Some(p)
        }
        None => None,
    };
    let script = match &json {
        Some(j) => {
            let p = dir.join("installa-app.cmd");
            let body = format!(
                "@echo off\r\n\
                 title Transfermon - installazione app con winget\r\n\
                 echo Installazione dei programmi del PC \"{}\" tramite winget.\r\n\
                 echo Potrebbero comparire richieste di autorizzazione (UAC): accettale.\r\n\
                 echo.\r\n\
                 winget import -i \"{}\" --accept-package-agreements --accept-source-agreements --ignore-unavailable --ignore-versions\r\n\
                 echo.\r\n\
                 echo Fine. Controlla sopra eventuali errori; i programmi non trovati da winget sono in programmi-installati.txt.\r\n\
                 pause\r\n",
                bundle.source_name,
                j.display()
            );
            std::fs::write(&p, body)?;
            Some(p)
        }
        None => None,
    };
    Ok(SavedApps {
        dir,
        json,
        list,
        script,
    })
}

/// Apre lo script di installazione in una nuova finestra della console.
pub fn launch_script(script: &Path) -> Result<()> {
    let mut cmd = Command::new("cmd");
    cmd.args([
        "/c",
        "start",
        "Transfermon - installazione app",
        &script.to_string_lossy(),
    ]);
    hide_window(&mut cmd);
    cmd.spawn().context("avvio dello script")?;
    Ok(())
}

pub fn open_folder(dir: &Path) -> Result<()> {
    Command::new("explorer").arg(dir).spawn().context("apertura cartella")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ids_by_segment() {
        let ids = vec![
            "Google.Chrome".to_string(),
            "Microsoft.VisualStudioCode".to_string(),
            "Python.Python.3.12".to_string(),
            "9NBLGGH4NNS1".to_string(),
        ];
        let mut apps = vec![
            InstalledApp { name: "Google Chrome".into(), ..Default::default() },
            InstalledApp { name: "Microsoft Visual Studio Code (User)".into(), ..Default::default() },
            InstalledApp { name: "Python 3.12.4 (64-bit)".into(), ..Default::default() },
            InstalledApp { name: "Qualcosa di sconosciuto".into(), ..Default::default() },
        ];
        attach_winget_ids(&mut apps, &ids);
        assert_eq!(apps[0].winget_id.as_deref(), Some("Google.Chrome"));
        assert_eq!(apps[1].winget_id.as_deref(), Some("Microsoft.VisualStudioCode"));
        assert_eq!(apps[2].winget_id.as_deref(), Some("Python.Python.3.12"));
        assert_eq!(apps[3].winget_id, None);
    }

    #[test]
    fn parses_export_json() {
        let json = r#"{"Sources":[{"Packages":[{"PackageIdentifier":"Google.Chrome"},{"PackageIdentifier":"7zip.7zip"}],"SourceDetails":{"Name":"winget"}}]}"#;
        assert_eq!(winget_ids(json), vec!["Google.Chrome", "7zip.7zip"]);
        assert!(winget_ids("non json").is_empty());
    }
}
