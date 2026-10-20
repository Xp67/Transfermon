//! Stato condiviso fra i thread di lavoro (discovery, trasferimento) e
//! l'interfaccia grafica.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

use rand::Rng;

use crate::apps::SavedApps;
use crate::discovery::Peer;
use crate::protocol::{AppsBundle, Role, Root};
use crate::sysinfo;
use crate::util::{self, lock};

/// Riassunto di un trasferimento in arrivo, mostrato al PC nuovo prima di accettare.
#[derive(Clone, Debug)]
pub struct IncomingSummary {
    pub peer_name: String,
    pub peer_user: String,
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// File già presenti e identici (stessa dimensione e data): non verranno ritrasmessi.
    pub skip_files: u64,
    pub skip_bytes: u64,
    pub apps: usize,
    pub winget: bool,
    /// Dove finirà ogni radice sul PC nuovo.
    pub roots: Vec<(Root, PathBuf)>,
}

/// Esito finale di un trasferimento (su entrambi i lati).
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub files_ok: u64,
    pub bytes: u64,
    /// (percorso, motivo) dei file non trasferiti.
    pub failed: Vec<(String, String)>,
    /// Solo sul PC nuovo: elenco programmi ricevuto.
    pub apps: Option<AppsBundle>,
    /// Solo sul PC nuovo: dove è stato salvato l'elenco programmi.
    pub apps_saved: Option<SavedApps>,
    pub elapsed: Duration,
}

#[derive(Clone, Debug)]
pub enum JobStatus {
    Idle,
    CollectingApps,
    Connecting(String),
    Pairing,
    /// Scambio dell'elenco dei file o confronto con il disco: testo per l'utente.
    Preparing(String),
    WaitingAccept,
    Incoming(IncomingSummary),
    Transferring,
    Finished(Outcome),
    Failed(String),
}

#[derive(Clone, Debug, Default)]
pub struct Progress {
    pub files_done: u64,
    pub files_total: u64,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub current: String,
    pub started: Option<Instant>,
}

pub struct Shared {
    pub my_id: u64,
    pub my_name: String,
    pub my_user: String,
    pub role: Mutex<Role>,
    pub tcp_port: AtomicU16,
    pub peers: Mutex<Vec<Peer>>,
    pub log: Mutex<Vec<String>>,
    pub progress: Mutex<Progress>,
    pub status: Mutex<JobStatus>,
    pub cancel: AtomicBool,
    pub shutdown: AtomicBool,
    pub pin: Mutex<String>,
    pub decision: Mutex<Option<mpsc::Sender<bool>>>,
    pub active_socket: Mutex<Option<TcpStream>>,
    started: Instant,
    log_file: Mutex<Option<File>>,
}

impl Default for Shared {
    fn default() -> Self {
        Self::new(false)
    }
}

impl Shared {
    /// `with_log_file`: scrive anche su `%LOCALAPPDATA%\Transfermon\transfermon.log`.
    pub fn new(with_log_file: bool) -> Self {
        let log_file = if with_log_file {
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(sysinfo::log_file_path())
                .ok()
        } else {
            None
        };
        Shared {
            my_id: rand::thread_rng().gen(),
            my_name: sysinfo::computer_name(),
            my_user: sysinfo::user_name(),
            role: Mutex::new(Role::Idle),
            tcp_port: AtomicU16::new(0),
            peers: Mutex::new(Vec::new()),
            log: Mutex::new(Vec::new()),
            progress: Mutex::new(Progress::default()),
            status: Mutex::new(JobStatus::Idle),
            cancel: AtomicBool::new(false),
            shutdown: AtomicBool::new(false),
            pin: Mutex::new(String::new()),
            decision: Mutex::new(None),
            active_socket: Mutex::new(None),
            started: Instant::now(),
            log_file: Mutex::new(log_file),
        }
    }

    pub fn log(&self, msg: impl Into<String>) {
        let line = format!("[{}] {}", util::elapsed_hms(self.started), msg.into());
        if let Some(f) = lock(&self.log_file).as_mut() {
            let _ = writeln!(f, "{} {}", util::now_unix(), line);
        }
        let mut log = lock(&self.log);
        log.push(line);
        if log.len() > 500 {
            let drop_n = log.len() - 500;
            log.drain(..drop_n);
        }
    }

    pub fn set_status(&self, s: JobStatus) {
        *lock(&self.status) = s;
    }

    pub fn status(&self) -> JobStatus {
        lock(&self.status).clone()
    }

    pub fn role(&self) -> Role {
        *lock(&self.role)
    }

    pub fn set_role(&self, r: Role) {
        *lock(&self.role) = r;
    }

    /// Genera un nuovo codice di collegamento a 6 cifre.
    pub fn new_pin(&self) -> String {
        let pin = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000u32));
        *lock(&self.pin) = pin.clone();
        pin
    }

    pub fn pin(&self) -> String {
        lock(&self.pin).clone()
    }

    /// Chiede l'interruzione del lavoro in corso e sblocca le letture di rete.
    pub fn request_cancel(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(s) = lock(&self.active_socket).as_ref() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }

    pub fn set_socket(&self, s: Option<TcpStream>) {
        *lock(&self.active_socket) = s;
    }

    pub fn start_progress(&self, files_total: u64, bytes_total: u64) {
        *lock(&self.progress) = Progress {
            files_total,
            bytes_total,
            started: Some(Instant::now()),
            ..Default::default()
        };
    }

    pub fn add_bytes(&self, n: u64) {
        lock(&self.progress).bytes_done += n;
    }

    pub fn file_done(&self) {
        lock(&self.progress).files_done += 1;
    }

    pub fn set_current(&self, s: &str) {
        lock(&self.progress).current = s.to_string();
    }

    pub fn progress(&self) -> Progress {
        lock(&self.progress).clone()
    }

    /// Risposta dell'utente del PC nuovo alla richiesta di trasferimento.
    pub fn decide(&self, accept: bool) {
        if let Some(tx) = lock(&self.decision).take() {
            let _ = tx.send(accept);
        }
    }
}
