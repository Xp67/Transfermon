//! Listener TCP del PC nuovo: accetta una connessione alla volta e la passa a
//! `transfer::run_receiver`. Dopo un trasferimento riuscito smette di ascoltare.

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::apps;
use crate::dest::DestMap;
use crate::protocol::Role;
use crate::secure::BadPin;
use crate::shared::{IncomingSummary, JobStatus, Shared};
use crate::transfer;
use crate::util::lock;

pub const DEFAULT_TCP_PORT: u16 = 47832;
const MAX_PIN_FAILURES: u32 = 3;

pub struct ReceiverService {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    shared: Arc<Shared>,
    pub addr: SocketAddr,
}

/// Mette il PC in ascolto, genera il codice e annuncia il ruolo in rete.
pub fn start(shared: Arc<Shared>, dest: DestMap) -> Result<ReceiverService> {
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, DEFAULT_TCP_PORT))
        .or_else(|_| TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)))
        .context("apertura della porta di ascolto")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    shared.tcp_port.store(addr.port(), Ordering::Relaxed);
    shared.set_role(Role::Receiver);
    shared.new_pin();
    shared.cancel.store(false, Ordering::SeqCst);
    shared.set_status(JobStatus::Idle);
    shared.log(format!("In ascolto sulla porta {}", addr.port()));

    let stop = Arc::new(AtomicBool::new(false));
    let handle = {
        let stop = Arc::clone(&stop);
        let shared = Arc::clone(&shared);
        thread::spawn(move || serve(listener, dest, shared, stop))
    };
    Ok(ReceiverService {
        stop,
        handle: Some(handle),
        shared,
        addr,
    })
}

fn serve(listener: TcpListener, dest: DestMap, shared: Arc<Shared>, stop: Arc<AtomicBool>) {
    let mut failures = 0u32;
    while !stop.load(Ordering::Relaxed) {
        let (stream, from) = match listener.accept() {
            Ok(x) => x,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(150));
                continue;
            }
            Err(e) => {
                shared.log(format!("Errore in ascolto: {e}"));
                thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        if stream.set_nonblocking(false).is_err() {
            continue;
        }
        shared.log(format!("Connessione in arrivo da {}", from.ip()));
        shared.cancel.store(false, Ordering::SeqCst);
        let pin = shared.pin();
        let mut decide = |summary: &IncomingSummary| -> bool {
            let (tx, rx) = mpsc::channel();
            *lock(&shared.decision) = Some(tx);
            shared.set_status(JobStatus::Incoming(summary.clone()));
            loop {
                match rx.recv_timeout(Duration::from_millis(300)) {
                    Ok(b) => return b,
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if shared.cancel.load(Ordering::Relaxed) || stop.load(Ordering::Relaxed) {
                            return false;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => return false,
                }
            }
        };
        match transfer::run_receiver(stream, &pin, &dest, &shared, &mut decide) {
            Ok(mut outcome) => {
                if let Some(bundle) = &outcome.apps {
                    match apps::save_bundle(bundle) {
                        Ok(saved) => {
                            shared.log(format!("Elenco programmi salvato in {}", saved.dir.display()));
                            outcome.apps_saved = Some(saved);
                        }
                        Err(e) => shared.log(format!("Salvataggio elenco programmi fallito: {e:#}")),
                    }
                }
                shared.set_status(JobStatus::Finished(outcome));
                break;
            }
            Err(e) => {
                if e.downcast_ref::<BadPin>().is_some() {
                    failures += 1;
                    shared.log(format!(
                        "Codice errato da {} (tentativo {failures}/{MAX_PIN_FAILURES})",
                        from.ip()
                    ));
                    if failures >= MAX_PIN_FAILURES {
                        shared.new_pin();
                        failures = 0;
                        shared.log("Troppi tentativi: generato un nuovo codice");
                    }
                    shared.set_status(JobStatus::Idle);
                } else {
                    shared.log(format!("Trasferimento interrotto: {e:#}"));
                    shared.set_status(JobStatus::Failed(format!("{e:#}")));
                }
            }
        }
    }
    shared.set_role(Role::Idle);
    shared.tcp_port.store(0, Ordering::Relaxed);
}

impl ReceiverService {
    /// Ferma l'ascolto e interrompe un'eventuale ricezione in corso.
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.shared.request_cancel();
        self.shared.decide(false);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for ReceiverService {
    fn drop(&mut self) {
        self.stop();
    }
}
