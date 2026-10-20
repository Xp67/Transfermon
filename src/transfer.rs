//! Motore di trasferimento: lato PC vecchio (`run_sender`) e lato PC nuovo
//! (`run_receiver`). Vedi `protocol` per la sequenza dei messaggi.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use filetime::FileTime;

use crate::dest::DestMap;
use crate::protocol::{
    bitset_count, bitset_get, bitset_new, bitset_set, AppsBundle, FileEntry, Manifest,
    ManifestHead, Msg, CHUNK_SIZE, MANIFEST_BATCH, PROTOCOL_VERSION,
};
use crate::scan::ScanResult;
use crate::secure;
use crate::shared::{IncomingSummary, JobStatus, Outcome, Shared};
use crate::util;

/// Limite di sicurezza sulle voci dichiarate dall'altro PC (memoria).
const MAX_ENTRIES: u64 = 50_000_000;

/// Cosa inviare: le scansioni selezionate e, opzionalmente, l'elenco programmi.
pub struct Plan {
    pub scans: Vec<Arc<ScanResult>>,
    pub apps: Option<AppsBundle>,
}

impl Plan {
    pub fn total_bytes(&self) -> u64 {
        self.scans.iter().map(|s| s.bytes).sum()
    }

    pub fn total_files(&self) -> usize {
        self.scans.iter().map(|s| s.files.len()).sum()
    }

    /// Manifest da inviare + percorso sorgente di ogni file (stesso indice).
    fn manifest(&self) -> (Manifest, Vec<PathBuf>) {
        let mut m = Manifest::default();
        let mut paths = Vec::with_capacity(self.total_files());
        for s in &self.scans {
            m.roots.push(s.root);
            m.dirs.extend(s.dirs.iter().cloned());
            for f in &s.files {
                paths.push(s.source_path(f));
                m.total_bytes += f.size;
                m.files.push(f.clone());
            }
        }
        m.apps = self.apps.clone();
        (m, paths)
    }
}

/// Lato PC vecchio: si collega, fa il pairing, invia manifest e file.
pub fn run_sender(addr: SocketAddr, pin: &str, plan: &Plan, shared: &Shared) -> Result<Outcome> {
    let r = sender_inner(addr, pin, plan, shared);
    shared.set_socket(None);
    r
}

fn sender_inner(addr: SocketAddr, pin: &str, plan: &Plan, shared: &Shared) -> Result<Outcome> {
    let started = Instant::now();
    shared.set_status(JobStatus::Connecting(addr.to_string()));
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(8))
        .with_context(|| format!("impossibile collegarsi a {addr}"))?;
    stream.set_nodelay(true)?;
    shared.set_socket(stream.try_clone().ok());

    shared.set_status(JobStatus::Pairing);
    let mut ss = secure::pair_sender(stream, pin)?;
    ss.send(&Msg::Hello {
        name: shared.my_name.clone(),
        user: shared.my_user.clone(),
        version: PROTOCOL_VERSION,
    })?;
    ss.flush()?;
    match ss.recv()? {
        Msg::Hello { name, version, .. } => {
            if version != PROTOCOL_VERSION {
                bail!("l'altro PC usa una versione diversa di Transfermon (protocollo {version}, qui {PROTOCOL_VERSION}): aggiorna entrambi i PC all'ultima versione");
            }
            shared.log(format!("Collegato al PC nuovo \"{name}\""));
        }
        other => bail!("risposta inattesa dal PC nuovo: {}", other.kind()),
    }

    let (mut manifest, paths) = plan.manifest();
    shared.log(format!(
        "Invio dell'elenco: {} file, {} cartelle, {}",
        manifest.files.len(),
        manifest.dirs.len(),
        util::fmt_bytes(manifest.total_bytes)
    ));
    shared.set_status(JobStatus::Preparing(format!(
        "Invio dell'elenco dei file al PC nuovo ({} file)",
        manifest.files.len()
    )));
    ss.send(&Msg::ManifestStart(ManifestHead {
        roots: manifest.roots.clone(),
        dirs: manifest.dirs.len() as u64,
        files: manifest.files.len() as u64,
        total_bytes: manifest.total_bytes,
        apps: manifest.apps.take(),
    }))?;
    for chunk in manifest.dirs.chunks(MANIFEST_BATCH) {
        ss.send(&Msg::ManifestDirs(chunk.to_vec()))?;
    }
    for chunk in manifest.files.chunks(MANIFEST_BATCH) {
        ss.send(&Msg::ManifestFiles(chunk.to_vec()))?;
        if shared.cancel.load(Ordering::Relaxed) {
            bail!("trasferimento annullato");
        }
    }
    ss.send(&Msg::ManifestEnd)?;
    ss.flush()?;

    shared.set_status(JobStatus::WaitingAccept);
    let skip: Vec<u8> = match ss.recv()? {
        Msg::Accept { skip } => skip,
        Msg::Reject => bail!("il PC nuovo ha rifiutato il trasferimento"),
        Msg::Error(e) => bail!("errore sul PC nuovo: {e}"),
        other => bail!("risposta inattesa dal PC nuovo: {}", other.kind()),
    };

    let mut total_bytes = 0u64;
    let mut total_files = 0u64;
    for (i, f) in manifest.files.iter().enumerate() {
        if !bitset_get(&skip, i) {
            total_bytes += f.size;
            total_files += 1;
        }
    }
    let skipped = bitset_count(&skip);
    if skipped > 0 {
        shared.log(format!(
            "{skipped} file sono già identici sul PC nuovo e non verranno ritrasmessi"
        ));
    }
    shared.start_progress(total_files, total_bytes);
    shared.set_status(JobStatus::Transferring);

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut files_ok = 0u64;
    for (i, entry) in manifest.files.iter().enumerate() {
        let index = i as u32;
        if bitset_get(&skip, i) {
            continue;
        }
        if shared.cancel.load(Ordering::Relaxed) {
            let _ = ss.send(&Msg::Error("annullato dal PC vecchio".into()));
            let _ = ss.flush();
            bail!("trasferimento annullato");
        }
        shared.set_current(&entry.rel);
        let mut file = match File::open(&paths[i]) {
            Ok(f) => f,
            Err(e) => {
                let reason = e.to_string();
                failed.push((entry.rel.clone(), reason.clone()));
                ss.send(&Msg::FileFailed { index, reason })?;
                shared.file_done();
                continue;
            }
        };
        let mut offset = 0u64;
        let mut ok = true;
        loop {
            let n = match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    let reason = e.to_string();
                    failed.push((entry.rel.clone(), reason.clone()));
                    ss.send(&Msg::FileFailed { index, reason })?;
                    ok = false;
                    break;
                }
            };
            ss.send(&Msg::FileData {
                index,
                offset,
                data: buf[..n].to_vec(),
            })?;
            offset += n as u64;
            shared.add_bytes(n as u64);
            if shared.cancel.load(Ordering::Relaxed) {
                let _ = ss.send(&Msg::Error("annullato dal PC vecchio".into()));
                let _ = ss.flush();
                bail!("trasferimento annullato");
            }
        }
        if ok {
            ss.send(&Msg::FileDone { index })?;
            files_ok += 1;
        }
        shared.file_done();
    }
    ss.send(&Msg::Finished)?;
    ss.flush()?;
    match ss.recv()? {
        Msg::Ack {
            files_ok: rok,
            failed: rfail,
        } => shared.log(format!(
            "Il PC nuovo conferma: {rok} file scritti, {rfail} non riusciti"
        )),
        Msg::Error(e) => bail!("errore sul PC nuovo: {e}"),
        other => bail!("risposta inattesa dal PC nuovo: {}", other.kind()),
    }
    Ok(Outcome {
        files_ok,
        bytes: shared.progress().bytes_done,
        failed,
        apps: None,
        apps_saved: None,
        elapsed: started.elapsed(),
    })
}

struct OpenFile {
    index: u32,
    file: File,
    path: PathBuf,
    offset: u64,
}

fn create_dest(dest: &DestMap, entry: &FileEntry) -> Result<(File, PathBuf), String> {
    let path = dest.resolve(entry.root, &entry.rel)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("creazione cartella: {e}"))?;
    }
    // Su Windows `File::create` fallisce sui file nascosti/sola lettura esistenti:
    // in quel caso lo si rimuove e si riprova.
    let file = match File::create(&path) {
        Ok(f) => f,
        Err(first) => {
            if path.exists() {
                let _ = fs::remove_file(&path);
                File::create(&path).map_err(|e| e.to_string())?
            } else {
                return Err(first.to_string());
            }
        }
    };
    Ok((file, path))
}

fn same_file_present(dest: &DestMap, f: &FileEntry) -> bool {
    let Ok(p) = dest.resolve(f.root, &f.rel) else {
        return false;
    };
    match fs::metadata(&p) {
        Ok(md) => md.is_file() && md.len() == f.size && util::unix_mtime(&md) == f.mtime,
        Err(_) => false,
    }
}

/// Riceve l'elenco a blocchi dopo `ManifestStart` e lo ricompone.
fn receive_manifest(ss: &mut secure::SecureStream, head: ManifestHead, shared: &Shared) -> Result<Manifest> {
    if head.files > MAX_ENTRIES || head.dirs > MAX_ENTRIES {
        bail!("elenco troppo grande ({} file, {} cartelle)", head.files, head.dirs);
    }
    let mut manifest = Manifest {
        roots: head.roots,
        dirs: Vec::with_capacity(head.dirs.min(1_000_000) as usize),
        files: Vec::with_capacity(head.files.min(1_000_000) as usize),
        total_bytes: head.total_bytes,
        apps: head.apps,
    };
    let mut last_status = Instant::now();
    loop {
        if shared.cancel.load(Ordering::Relaxed) {
            bail!("trasferimento annullato");
        }
        match ss.recv()? {
            Msg::ManifestDirs(d) => manifest.dirs.extend(d),
            Msg::ManifestFiles(f) => manifest.files.extend(f),
            Msg::ManifestEnd => break,
            Msg::Error(e) => bail!("il PC vecchio ha interrotto: {e}"),
            other => bail!("messaggio inatteso dal PC vecchio: {}", other.kind()),
        }
        if manifest.files.len() as u64 > head.files || manifest.dirs.len() as u64 > head.dirs {
            bail!("elenco più lungo del dichiarato");
        }
        if last_status.elapsed() > Duration::from_millis(300) {
            shared.set_status(JobStatus::Preparing(format!(
                "Ricezione dell'elenco dei file ({} di {})",
                manifest.files.len(),
                head.files
            )));
            last_status = Instant::now();
        }
    }
    Ok(manifest)
}

/// Lato PC nuovo: pairing, ricezione manifest, decisione dell'utente, scrittura.
pub fn run_receiver(
    stream: TcpStream,
    pin: &str,
    dest: &DestMap,
    shared: &Shared,
    decide: &mut dyn FnMut(&IncomingSummary) -> bool,
) -> Result<Outcome> {
    let r = receiver_inner(stream, pin, dest, shared, decide);
    shared.set_socket(None);
    r
}

fn receiver_inner(
    stream: TcpStream,
    pin: &str,
    dest: &DestMap,
    shared: &Shared,
    decide: &mut dyn FnMut(&IncomingSummary) -> bool,
) -> Result<Outcome> {
    let started = Instant::now();
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(180)))?;
    shared.set_socket(stream.try_clone().ok());
    shared.set_status(JobStatus::Pairing);

    let mut ss = secure::pair_receiver(stream, pin)?;
    let (peer_name, peer_user) = match ss.recv()? {
        Msg::Hello {
            name,
            user,
            version,
        } => {
            if version != PROTOCOL_VERSION {
                let _ = ss.send(&Msg::Error(format!(
                    "versione di protocollo diversa ({version} contro {PROTOCOL_VERSION})"
                )));
                let _ = ss.flush();
                bail!("il PC vecchio usa una versione diversa di Transfermon (protocollo {version}, qui {PROTOCOL_VERSION}): aggiorna entrambi i PC all'ultima versione");
            }
            (name, user)
        }
        other => bail!("messaggio inatteso dal PC vecchio: {}", other.kind()),
    };
    ss.send(&Msg::Hello {
        name: shared.my_name.clone(),
        user: shared.my_user.clone(),
        version: PROTOCOL_VERSION,
    })?;
    ss.flush()?;
    shared.log(format!("Collegato al PC vecchio \"{peer_name}\" (utente {peer_user})"));

    let head = match ss.recv()? {
        Msg::ManifestStart(h) => h,
        other => bail!("messaggio inatteso dal PC vecchio: {}", other.kind()),
    };
    shared.set_status(JobStatus::Preparing(format!(
        "Ricezione dell'elenco dei file (0 di {})",
        head.files
    )));
    let manifest = receive_manifest(&mut ss, head, shared)?;
    shared.log(format!(
        "Elenco ricevuto: {} file, {} cartelle, {}",
        manifest.files.len(),
        manifest.dirs.len(),
        util::fmt_bytes(manifest.total_bytes)
    ));

    shared.set_status(JobStatus::Preparing(
        "Confronto con i file già presenti su questo PC".into(),
    ));
    let mut skip = bitset_new(manifest.files.len());
    let mut skip_files = 0u64;
    let mut skip_bytes = 0u64;
    for (i, f) in manifest.files.iter().enumerate() {
        if same_file_present(dest, f) {
            bitset_set(&mut skip, i);
            skip_files += 1;
            skip_bytes += f.size;
        }
    }
    let summary = IncomingSummary {
        peer_name: peer_name.clone(),
        peer_user,
        files: manifest.files.len() as u64,
        dirs: manifest.dirs.len() as u64,
        bytes: manifest.total_bytes,
        skip_files,
        skip_bytes,
        apps: manifest.apps.as_ref().map(|a| a.installed.len()).unwrap_or(0),
        winget: manifest
            .apps
            .as_ref()
            .map(|a| a.winget_export_json.is_some())
            .unwrap_or(false),
        roots: manifest
            .roots
            .iter()
            .map(|r| (*r, dest.root_dir(*r)))
            .collect(),
    };
    if !decide(&summary) {
        let _ = ss.send(&Msg::Reject);
        let _ = ss.flush();
        bail!("trasferimento rifiutato");
    }
    ss.send(&Msg::Accept { skip: skip.clone() })?;
    ss.flush()?;

    let mut failed: Vec<(String, String)> = Vec::new();
    for d in &manifest.dirs {
        match dest.resolve(d.root, &d.rel) {
            Ok(p) => {
                if let Err(e) = fs::create_dir_all(&p) {
                    failed.push((d.rel.clone(), format!("creazione cartella: {e}")));
                }
            }
            Err(e) => failed.push((d.rel.clone(), e)),
        }
    }
    let files_total = manifest.files.len() as u64 - skip_files;
    shared.start_progress(files_total, manifest.total_bytes.saturating_sub(skip_bytes));
    shared.set_status(JobStatus::Transferring);

    let mut open: Option<OpenFile> = None;
    let mut discard: Option<u32> = None;
    let mut files_ok = 0u64;
    loop {
        if shared.cancel.load(Ordering::Relaxed) {
            let _ = ss.send(&Msg::Error("annullato dal PC nuovo".into()));
            let _ = ss.flush();
            if let Some(o) = open.take() {
                drop(o.file);
                let _ = fs::remove_file(&o.path);
            }
            bail!("trasferimento annullato");
        }
        match ss.recv()? {
            Msg::FileData {
                index,
                offset,
                data,
            } => {
                if discard == Some(index) {
                    shared.add_bytes(data.len() as u64);
                    continue;
                }
                let entry = manifest
                    .files
                    .get(index as usize)
                    .with_context(|| format!("indice file sconosciuto {index}"))?;
                if open.as_ref().map(|o| o.index) != Some(index) {
                    if let Some(o) = open.take() {
                        // Il protocollo prevede FileDone prima del file successivo:
                        // un file lasciato a metà viene considerato fallito.
                        drop(o.file);
                        let _ = fs::remove_file(&o.path);
                    }
                    shared.set_current(&entry.rel);
                    match create_dest(dest, entry) {
                        Ok((file, path)) => {
                            open = Some(OpenFile {
                                index,
                                file,
                                path,
                                offset: 0,
                            })
                        }
                        Err(e) => {
                            failed.push((entry.rel.clone(), e));
                            discard = Some(index);
                            shared.add_bytes(data.len() as u64);
                            continue;
                        }
                    }
                }
                let o = open.as_mut().expect("file aperto");
                if o.offset != offset {
                    bail!("sequenza dati incoerente per {}", entry.rel);
                }
                if let Err(e) = o.file.write_all(&data) {
                    failed.push((entry.rel.clone(), format!("scrittura: {e}")));
                    let o = open.take().expect("file aperto");
                    drop(o.file);
                    let _ = fs::remove_file(&o.path);
                    discard = Some(index);
                    shared.add_bytes(data.len() as u64);
                    continue;
                }
                o.offset += data.len() as u64;
                shared.add_bytes(data.len() as u64);
            }
            Msg::FileDone { index } => {
                let entry = manifest
                    .files
                    .get(index as usize)
                    .with_context(|| format!("indice file sconosciuto {index}"))?;
                if discard == Some(index) {
                    discard = None;
                    shared.file_done();
                    continue;
                }
                let path = match open.take() {
                    Some(o) if o.index == index => {
                        // Niente sync per file: con centinaia di migliaia di file
                        // piccoli costerebbe decine di minuti; il sistema operativo
                        // scrive su disco per conto suo.
                        drop(o.file);
                        o.path
                    }
                    other => {
                        if let Some(o) = other {
                            drop(o.file);
                            let _ = fs::remove_file(&o.path);
                        }
                        // File vuoto: nessun FileData lo ha preceduto.
                        shared.set_current(&entry.rel);
                        match create_dest(dest, entry) {
                            Ok((file, path)) => {
                                drop(file);
                                path
                            }
                            Err(e) => {
                                failed.push((entry.rel.clone(), e));
                                shared.file_done();
                                continue;
                            }
                        }
                    }
                };
                let _ = filetime::set_file_mtime(&path, FileTime::from_unix_time(entry.mtime, 0));
                files_ok += 1;
                shared.file_done();
            }
            Msg::FileFailed { index, reason } => {
                let rel = manifest
                    .files
                    .get(index as usize)
                    .map(|f| f.rel.clone())
                    .unwrap_or_else(|| format!("#{index}"));
                failed.push((rel, format!("sul PC vecchio: {reason}")));
                if let Some(o) = open.take() {
                    drop(o.file);
                    if o.index == index {
                        let _ = fs::remove_file(&o.path);
                    }
                }
                if discard == Some(index) {
                    discard = None;
                }
                shared.file_done();
            }
            Msg::Finished => break,
            Msg::Error(e) => {
                if let Some(o) = open.take() {
                    drop(o.file);
                    let _ = fs::remove_file(&o.path);
                }
                bail!("il PC vecchio ha interrotto: {e}");
            }
            other => bail!("messaggio inatteso dal PC vecchio: {}", other.kind()),
        }
    }
    ss.send(&Msg::Ack {
        files_ok,
        failed: failed.len() as u32,
    })?;
    ss.flush()?;
    shared.log(format!(
        "Ricezione completata: {files_ok} file scritti, {} non riusciti",
        failed.len()
    ));
    Ok(Outcome {
        files_ok,
        bytes: shared.progress().bytes_done,
        failed,
        apps: manifest.apps,
        apps_saved: None,
        elapsed: started.elapsed(),
    })
}
