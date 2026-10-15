//! Interfaccia grafica (egui): schermata iniziale, PC vecchio, PC nuovo.
//! L'aspetto (foglio bianco su carta, un colore d'azione) è in `theme`.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use egui::{Align, Layout, RichText};
use transfermon::apps;
use transfermon::dest::DestMap;
use transfermon::discovery;
use transfermon::protocol::{Role, Root};
use transfermon::receiver_service::{self, ReceiverService, DEFAULT_TCP_PORT};
use transfermon::scan::{self, ScanResult};
use transfermon::secure::BadPin;
use transfermon::shared::{IncomingSummary, JobStatus, Outcome, Progress, Shared};
use transfermon::sysinfo::{self, KnownFolders, LocalIp};
use transfermon::transfer::{self, Plan};
use transfermon::util::{fmt_bytes, fmt_duration, lock};

use crate::theme::{self, Kind, Theme, ERR, INK, MUTED, OK, PRIMARY};

const COLUMN_WIDTH: f32 = 880.0;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Home,
    SenderSetup,
    SenderRun,
    Receiver,
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum ScanKey {
    Root(Root),
    Extra(PathBuf),
}

enum ScanState {
    Pending,
    Done(Arc<ScanResult>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Peer(u64),
    Manual,
}

pub struct App {
    shared: Arc<Shared>,
    theme: Theme,
    kf: KnownFolders,
    screen: Screen,
    ips: Vec<LocalIp>,
    ips_at: Instant,
    show_log: bool,
    // PC vecchio
    checks: HashMap<Root, bool>,
    extra: Vec<PathBuf>,
    include_apps: bool,
    scans: Arc<Mutex<HashMap<ScanKey, ScanState>>>,
    scan_cancel: Arc<AtomicBool>,
    pin: String,
    target: Target,
    manual_addr: String,
    // PC nuovo
    receiver: Option<ReceiverService>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, start: Option<String>) -> Self {
        let mut app = Self::build(cc);
        match start.as_deref() {
            Some("receiver") => app.enter_receiver(),
            Some("sender") => app.enter_sender(),
            _ => {}
        }
        app
    }

    fn build(cc: &eframe::CreationContext<'_>) -> Self {
        let theme = Theme::install(&cc.egui_ctx);
        let shared = Arc::new(Shared::new(true));
        shared.log(format!(
            "Transfermon avviato su {} (utente {})",
            shared.my_name, shared.my_user
        ));
        discovery::spawn(Arc::clone(&shared));
        let checks = Root::KNOWN.iter().map(|r| (*r, r.default_on())).collect();
        App {
            shared,
            theme,
            kf: KnownFolders::detect(),
            screen: Screen::Home,
            ips: sysinfo::local_ipv4s(),
            ips_at: Instant::now(),
            show_log: false,
            checks,
            extra: Vec::new(),
            include_apps: true,
            scans: Arc::new(Mutex::new(HashMap::new())),
            scan_cancel: Arc::new(AtomicBool::new(false)),
            pin: String::new(),
            target: Target::Manual,
            manual_addr: String::new(),
            receiver: None,
        }
    }

    fn ip_list(&self) -> String {
        if self.ips.is_empty() {
            "nessuna rete".to_string()
        } else {
            self.ips
                .iter()
                .map(|i| i.ip.to_string())
                .collect::<Vec<_>>()
                .join(" e ")
        }
    }

    // ----- navigazione -----

    fn enter_sender(&mut self) {
        self.stop_receiver();
        self.shared.set_role(Role::Sender);
        self.shared.set_status(JobStatus::Idle);
        self.screen = Screen::SenderSetup;
        let peers = lock(&self.shared.peers).clone();
        if let Some(p) = peers.iter().find(|p| p.role == Role::Receiver) {
            self.target = Target::Peer(p.id);
        }
        for r in Root::KNOWN {
            self.spawn_scan(ScanKey::Root(r));
        }
        for e in self.extra.clone() {
            self.spawn_scan(ScanKey::Extra(e));
        }
    }

    fn enter_receiver(&mut self) {
        self.stop_receiver();
        match receiver_service::start(Arc::clone(&self.shared), DestMap::system()) {
            Ok(s) => {
                self.receiver = Some(s);
                self.screen = Screen::Receiver;
            }
            Err(e) => self
                .shared
                .log(format!("Impossibile mettersi in ascolto: {e:#}")),
        }
    }

    fn stop_receiver(&mut self) {
        if let Some(mut s) = self.receiver.take() {
            s.stop();
        }
    }

    fn back_home(&mut self) {
        self.shared.request_cancel();
        self.stop_receiver();
        self.shared.cancel.store(false, Ordering::SeqCst);
        self.shared.set_role(Role::Idle);
        self.shared.set_status(JobStatus::Idle);
        self.screen = Screen::Home;
    }

    // ----- scansione -----

    fn spawn_scan(&self, key: ScanKey) {
        {
            let mut cache = lock(&self.scans);
            if cache.contains_key(&key) {
                return;
            }
            cache.insert(key.clone(), ScanState::Pending);
        }
        let scans = Arc::clone(&self.scans);
        let kf = self.kf.clone();
        let cancel = Arc::clone(&self.scan_cancel);
        let shared = Arc::clone(&self.shared);
        thread::spawn(move || {
            let (root, base) = match &key {
                ScanKey::Root(r) => (
                    *r,
                    kf.path_for(*r).map(|p| p.to_path_buf()).unwrap_or_default(),
                ),
                ScanKey::Extra(p) => (Root::Absolute, p.clone()),
            };
            let res = scan::scan(root, &base, &kf, &cancel);
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            let label = match &key {
                ScanKey::Root(r) => r.label().to_string(),
                ScanKey::Extra(p) => p.display().to_string(),
            };
            shared.log(format!(
                "Scansione {label}: {} file, {}{}",
                res.files.len(),
                fmt_bytes(res.bytes),
                if res.errors.is_empty() {
                    String::new()
                } else {
                    format!(", {} elementi saltati", res.errors.len())
                }
            ));
            lock(&scans).insert(key, ScanState::Done(Arc::new(res)));
        });
    }

    fn rescan(&mut self) {
        self.scan_cancel.store(true, Ordering::SeqCst);
        self.scan_cancel = Arc::new(AtomicBool::new(false));
        lock(&self.scans).clear();
        for r in Root::KNOWN {
            self.spawn_scan(ScanKey::Root(r));
        }
        for e in self.extra.clone() {
            self.spawn_scan(ScanKey::Extra(e));
        }
    }

    fn selected_keys(&self) -> Vec<ScanKey> {
        Root::KNOWN
            .iter()
            .filter(|r| self.checks.get(r).copied().unwrap_or(false))
            .map(|r| ScanKey::Root(*r))
            .chain(self.extra.iter().cloned().map(ScanKey::Extra))
            .collect()
    }

    /// (file, byte, c'è ancora qualcosa in calcolo?)
    fn selected_totals(&self) -> (u64, u64, bool) {
        let cache = lock(&self.scans);
        let mut files = 0u64;
        let mut bytes = 0u64;
        let mut pending = false;
        for k in self.selected_keys() {
            match cache.get(&k) {
                Some(ScanState::Done(r)) => {
                    files += r.files.len() as u64;
                    bytes += r.bytes;
                }
                _ => pending = true,
            }
        }
        (files, bytes, pending)
    }

    // ----- destinazione -----

    fn target_addr(&self) -> Result<SocketAddr, String> {
        match self.target {
            Target::Peer(id) => {
                let peers = lock(&self.shared.peers);
                let p = peers
                    .iter()
                    .find(|p| p.id == id)
                    .ok_or("Il PC nuovo selezionato non è più visibile in rete")?;
                if p.role != Role::Receiver || p.tcp_port == 0 {
                    return Err("Il PC selezionato non è in modalità ricezione".into());
                }
                Ok(SocketAddr::new(p.ip, p.tcp_port))
            }
            Target::Manual => {
                let s = self.manual_addr.trim();
                if s.is_empty() {
                    return Err("Inserisci l'indirizzo del PC nuovo".into());
                }
                if let Ok(a) = s.parse::<SocketAddr>() {
                    return Ok(a);
                }
                if let Ok(ip) = s.parse::<IpAddr>() {
                    return Ok(SocketAddr::new(ip, DEFAULT_TCP_PORT));
                }
                let (host, port) = match s.rsplit_once(':') {
                    Some((h, p)) if p.parse::<u16>().is_ok() => {
                        (h, p.parse::<u16>().unwrap_or(DEFAULT_TCP_PORT))
                    }
                    _ => (s, DEFAULT_TCP_PORT),
                };
                (host, port)
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut it| it.next())
                    .ok_or_else(|| format!("Indirizzo non valido: {s}"))
            }
        }
    }

    /// Controllo sintattico veloce (senza DNS) per abilitare il pulsante.
    fn target_plausible(&self) -> bool {
        match self.target {
            Target::Peer(_) => self.target_addr().is_ok(),
            Target::Manual => !self.manual_addr.trim().is_empty(),
        }
    }

    fn start_sender(&mut self) {
        let addr = match self.target_addr() {
            Ok(a) => a,
            Err(e) => {
                self.shared.log(e);
                return;
            }
        };
        let mut scans = Vec::new();
        {
            let cache = lock(&self.scans);
            for k in self.selected_keys() {
                match cache.get(&k) {
                    Some(ScanState::Done(r)) => scans.push(Arc::clone(r)),
                    _ => {
                        self.shared.log("Scansione non ancora completata");
                        return;
                    }
                }
            }
        }
        let pin = self.pin.clone();
        let include_apps = self.include_apps;
        let shared = Arc::clone(&self.shared);
        shared.cancel.store(false, Ordering::SeqCst);
        shared.set_status(JobStatus::Idle);
        self.screen = Screen::SenderRun;
        thread::spawn(move || {
            let apps = if include_apps {
                shared.set_status(JobStatus::CollectingApps);
                let name = shared.my_name.clone();
                let log = |s: String| shared.log(s);
                Some(apps::collect(&name, &log))
            } else {
                None
            };
            let plan = Plan { scans, apps };
            match transfer::run_sender(addr, &pin, &plan, &shared) {
                Ok(o) => {
                    shared.log(format!(
                        "Trasferimento completato: {} file, {}",
                        o.files_ok,
                        fmt_bytes(o.bytes)
                    ));
                    shared.set_status(JobStatus::Finished(o));
                }
                Err(e) => {
                    let msg = friendly_error(&e);
                    shared.log(format!("Errore: {msg}"));
                    shared.set_status(JobStatus::Failed(msg));
                }
            }
        });
    }

    // ----- cornice: barra superiore, registro -----

    fn top_bar(&mut self, root: &mut egui::Ui) {
        egui::Panel::top("top")
            .frame(egui::Frame::NONE)
            .exact_size(58.0)
            .show_separator_line(false)
            .show(root, |ui| {
                theme::paint_header(ui.painter(), ui.max_rect());
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                    ui.add_space(24.0);
                    ui.label(self.theme.display("Transfermon", 20.0));
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new(format!(
                            "{}, utente {}",
                            self.shared.my_name, self.shared.my_user
                        ))
                        .color(MUTED),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.add_space(24.0);
                        ui.checkbox(&mut self.show_log, "Registro");
                    });
                });
            });
    }

    fn log_panel(&self, root: &mut egui::Ui) {
        egui::Panel::bottom("log")
            .frame(egui::Frame::NONE)
            .resizable(true)
            .default_size(160.0)
            .show_separator_line(false)
            .show(root, |ui| {
                theme::paint_footer(ui.painter(), ui.max_rect());
                egui::Frame::NONE.inner_margin(12.0).show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .stick_to_bottom(true)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            for line in lock(&self.shared.log).iter() {
                                ui.label(RichText::new(line).monospace().size(12.0).color(MUTED));
                            }
                        });
                });
            });
    }

    // ----- schermate -----

    fn home(&mut self, ui: &mut egui::Ui) {
        ui.add_space(28.0);
        let mut go_sender = false;
        let mut go_receiver = false;
        theme::sheet(ui, |ui| {
            ui.label(self.theme.display("Sposta tutto dal PC vecchio a quello nuovo.", 30.0));
            ui.add_space(2.0);
            ui.label(
                RichText::new(
                    "File, impostazioni e programmi passano direttamente da un computer \
                     all'altro, cifrati, senza uscire dalla tua rete.",
                )
                .size(16.0)
                .color(MUTED),
            );
            ui.add_space(22.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(18.0, 14.0);
                if theme::tile(
                    ui,
                    &self.theme,
                    "Questo è il PC vecchio",
                    "Invia tutto quello che c'è su questo computer.",
                )
                .clicked()
                {
                    go_sender = true;
                }
                if theme::tile(
                    ui,
                    &self.theme,
                    "Questo è il PC nuovo",
                    "Ricevi tutto su questo computer.",
                )
                .clicked()
                {
                    go_receiver = true;
                }
            });
            ui.add_space(10.0);
            ui.label(
                RichText::new(format!(
                    "Questo computer è {}, utente {}, indirizzo {}.",
                    self.shared.my_name,
                    self.shared.my_user,
                    self.ip_list()
                ))
                .size(13.5)
                .color(MUTED),
            );

            theme::rule(ui);
            ui.label(self.theme.display("In rete adesso", 19.0));
            ui.add_space(4.0);
            let peers = lock(&self.shared.peers).clone();
            if peers.is_empty() {
                ui.label(
                    RichText::new(
                        "Nessun altro Transfermon in rete per ora. Aprilo anche sull'altro \
                         computer, collegato alla stessa rete Wi-Fi o via cavo. Se Windows chiede \
                         il permesso per il firewall, consenti l'accesso alle reti private.",
                    )
                    .color(MUTED),
                );
            }
            for p in &peers {
                ui.horizontal(|ui| {
                    theme::dot(ui, if p.role == Role::Receiver { OK } else { PRIMARY });
                    ui.label(self.theme.bold(&p.name));
                    ui.label(
                        RichText::new(format!("utente {}, {}, {}", p.user, p.ip, p.role.label()))
                            .color(MUTED),
                    );
                });
            }
        });
        if go_sender {
            self.enter_sender();
        }
        if go_receiver {
            self.enter_receiver();
        }
        ui.add_space(16.0);
        ui.label(
            RichText::new(
                "Come funziona: sul PC nuovo scegli «PC nuovo» e compare un codice. Sul PC \
                 vecchio scegli «PC vecchio», seleziona il PC nuovo, inserisci il codice e scegli \
                 cosa inviare.",
            )
            .size(13.5)
            .color(MUTED),
        );
        ui.add_space(28.0);
    }

    fn sender_setup(&mut self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        ui.label(self.theme.display("Invia dal PC vecchio", 28.0));
        ui.add_space(12.0);

        let mut add_folder = false;
        let mut remove: Option<usize> = None;
        let mut rescan = false;
        let mut start = false;
        let mut back = false;
        // Calcolato prima di prendere il lock sulla cache delle scansioni, che
        // resta tenuto per tutta la tabella: `selected_totals` lo riprenderebbe.
        let (total_files, total_bytes, pending) = self.selected_totals();
        theme::sheet(ui, |ui| {
            theme::step_title(ui, &self.theme, "1", "Il PC nuovo");
            let peers = lock(&self.shared.peers).clone();
            let receivers: Vec<_> = peers
                .iter()
                .filter(|p| p.role == Role::Receiver && p.tcp_port != 0)
                .collect();
            if receivers.is_empty() {
                ui.label(
                    RichText::new(
                        "Nessun PC in modalità ricezione trovato in rete. Sul PC nuovo apri \
                         Transfermon e scegli «PC nuovo».",
                    )
                    .color(MUTED),
                );
            }
            for p in &receivers {
                let text = format!("{}  (utente {}, {}:{})", p.name, p.user, p.ip, p.tcp_port);
                ui.radio_value(&mut self.target, Target::Peer(p.id), text);
            }
            for p in peers.iter().filter(|p| p.role != Role::Receiver) {
                ui.label(
                    RichText::new(format!("{} ({}): {}", p.name, p.ip, p.role.label()))
                        .color(MUTED),
                );
            }
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.target, Target::Manual, "Indirizzo scritto a mano:");
                ui.add_enabled(
                    self.target == Target::Manual,
                    egui::TextEdit::singleline(&mut self.manual_addr)
                        .hint_text(format!("es. 192.168.1.10:{DEFAULT_TCP_PORT}"))
                        .desired_width(220.0),
                );
                theme::help(
                    ui,
                    &self.theme,
                    "Serve solo se la ricerca automatica non trova il PC nuovo (firewall, reti \
                     separate). L'indirizzo è mostrato sul PC nuovo sotto il codice.",
                );
            });

            theme::rule(ui);
            ui.horizontal(|ui| {
                theme::step_title(ui, &self.theme, "2", "Il codice mostrato sul PC nuovo");
                ui.add_space(8.0);
                let r = ui.add(
                    egui::TextEdit::singleline(&mut self.pin)
                        .hint_text("6 cifre")
                        .desired_width(120.0)
                        .font(egui::FontId::new(20.0, self.theme.display.clone())),
                );
                if r.changed() {
                    self.pin.retain(|c| c.is_ascii_digit());
                    self.pin.truncate(6);
                }
            });

            theme::rule(ui);
            theme::step_title(ui, &self.theme, "3", "Cosa inviare");
            let scans = Arc::clone(&self.scans);
            let cache = lock(&scans);
            egui::Grid::new("roots")
                .num_columns(3)
                .striped(true)
                .spacing([20.0, 8.0])
                .min_col_width(150.0)
                .show(ui, |ui| {
                    for root in Root::KNOWN {
                        let on = self.checks.entry(root).or_insert_with(|| root.default_on());
                        ui.horizontal(|ui| {
                            ui.checkbox(on, root.label());
                            theme::help(ui, &self.theme, root.hint());
                        });
                        ui.label(
                            self.theme.mono(
                                self.kf
                                    .path_for(root)
                                    .map(|p| p.display().to_string())
                                    .unwrap_or_default(),
                            ),
                        );
                        ui.label(scan_cell(cache.get(&ScanKey::Root(root))));
                        ui.end_row();
                    }
                    for (i, e) in self.extra.iter().enumerate() {
                        ui.horizontal(|ui| {
                            if theme::button(ui, &self.theme, "Togli", Kind::Secondary).clicked() {
                                remove = Some(i);
                            }
                            ui.label("Cartella aggiuntiva");
                            theme::help(ui, &self.theme, Root::Absolute.hint());
                        });
                        ui.label(self.theme.mono(e.display().to_string()));
                        ui.label(scan_cell(cache.get(&ScanKey::Extra(e.clone()))));
                        ui.end_row();
                    }
                });
            drop(cache);
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if theme::button(ui, &self.theme, "Aggiungi una cartella", Kind::Secondary).clicked() {
                    add_folder = true;
                }
                if theme::button(ui, &self.theme, "Ricalcola le dimensioni", Kind::Secondary)
                    .on_hover_text("Rifà la scansione delle cartelle")
                    .clicked()
                {
                    rescan = true;
                }
            });
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.checkbox(
                    &mut self.include_apps,
                    "Elenco dei programmi installati, per reinstallarli con winget sul PC nuovo",
                );
                theme::help(
                    ui,
                    &self.theme,
                    "I programmi non si possono copiare: sul PC nuovo winget li reinstalla \
                     dall'elenco, mentre le loro impostazioni arrivano con AppData. I programmi \
                     che winget non conosce compaiono in un elenco per l'installazione manuale.",
                );
            });

            theme::rule(ui);
            if pending {
                theme::wait_line(ui, "Calcolo delle dimensioni in corso", false);
            } else {
                ui.label(self.theme.display(
                    format!("Da inviare: {total_files} file, {}", fmt_bytes(total_bytes)),
                    19.0,
                ));
            }
            ui.label(
                RichText::new(
                    "Esclusi automaticamente: cache e file temporanei, file OneDrive non \
                     scaricati, Docker, app dello Store, file di sistema del profilo. I file già \
                     identici sul PC nuovo non vengono ritrasmessi.",
                )
                .size(13.0)
                .color(MUTED),
            );
            ui.add_space(14.0);
            let mut missing: Vec<&str> = Vec::new();
            if pending {
                missing.push("attendi il calcolo delle dimensioni");
            }
            if total_files == 0 && !self.include_apps {
                missing.push("seleziona almeno una cartella");
            }
            if self.pin.len() != 6 {
                missing.push("inserisci il codice a 6 cifre");
            }
            if !self.target_plausible() {
                missing.push("scegli il PC nuovo");
            }
            let ready = missing.is_empty();
            ui.horizontal(|ui| {
                ui.add_enabled_ui(ready, |ui| {
                    if theme::button_sized(
                        ui,
                        &self.theme,
                        "Avvia il trasferimento",
                        Kind::Primary,
                        egui::vec2(210.0, 40.0),
                    )
                    .clicked()
                    {
                        start = true;
                    }
                });
                if theme::button(ui, &self.theme, "Indietro", Kind::Secondary).clicked() {
                    back = true;
                }
                if !ready {
                    ui.label(
                        RichText::new(format!("Per avviare: {}.", missing.join(", ")))
                            .color(MUTED),
                    );
                }
            });
        });
        if let Some(i) = remove {
            let p = self.extra.remove(i);
            lock(&self.scans).remove(&ScanKey::Extra(p));
        }
        if add_folder {
            if let Some(p) = rfd::FileDialog::new()
                .set_title("Scegli la cartella da aggiungere")
                .pick_folder()
            {
                if !self.extra.contains(&p) {
                    self.extra.push(p.clone());
                    self.spawn_scan(ScanKey::Extra(p));
                }
            }
        }
        if rescan {
            self.rescan();
        }
        if start {
            self.start_sender();
        }
        if back {
            self.back_home();
        }
        ui.add_space(28.0);
    }

    fn sender_run(&mut self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        ui.label(self.theme.display("Trasferimento dal PC vecchio", 28.0));
        ui.add_space(12.0);
        let status = self.shared.status();
        let mut action: Option<fn(&mut App)> = None;
        theme::sheet(ui, |ui| {
            match &status {
                JobStatus::Idle => theme::wait_line(ui, "Avvio", false),
                JobStatus::CollectingApps => theme::wait_line(
                    ui,
                    "Raccolta dell'elenco programmi con winget: può richiedere un minuto",
                    false,
                ),
                JobStatus::Connecting(a) => theme::wait_line(ui, &format!("Collegamento a {a}"), false),
                JobStatus::Pairing => theme::wait_line(ui, "Verifica del codice", false),
                JobStatus::WaitingAccept => theme::wait_line(
                    ui,
                    "In attesa che il PC nuovo accetti il trasferimento",
                    false,
                ),
                JobStatus::Transferring => progress_ui(ui, &self.theme, &self.shared.progress()),
                JobStatus::Incoming(_) => {}
                JobStatus::Finished(o) => finished_ui(ui, &self.theme, o, "inviati"),
                JobStatus::Failed(m) => failed_ui(ui, &self.theme, "Trasferimento non riuscito", m),
            }
            theme::rule(ui);
            ui.horizontal(|ui| match &status {
                JobStatus::Finished(_) | JobStatus::Failed(_) => {
                    if theme::button(ui, &self.theme, "Nuovo trasferimento", Kind::Primary).clicked() {
                        action = Some(|app| {
                            app.shared.set_status(JobStatus::Idle);
                            app.screen = Screen::SenderSetup;
                        });
                    }
                    if theme::button(ui, &self.theme, "Torna all'inizio", Kind::Secondary).clicked() {
                        action = Some(|app| app.back_home());
                    }
                }
                _ => {
                    if theme::button(ui, &self.theme, "Annulla", Kind::Secondary).clicked() {
                        action = Some(|app| app.shared.request_cancel());
                    }
                }
            });
        });
        if let Some(f) = action {
            f(self);
        }
        ui.add_space(28.0);
    }

    fn receiver(&mut self, ui: &mut egui::Ui) {
        ui.add_space(24.0);
        ui.label(self.theme.display("Ricevi sul PC nuovo", 28.0));
        ui.add_space(12.0);
        let status = self.shared.status();
        let port = self
            .receiver
            .as_ref()
            .map(|r| r.addr.port())
            .unwrap_or(DEFAULT_TCP_PORT);
        let mut action: Option<fn(&mut App)> = None;
        theme::sheet(ui, |ui| match &status {
            JobStatus::Idle | JobStatus::Failed(_) => {
                if let JobStatus::Failed(m) = &status {
                    failed_ui(ui, &self.theme, "Trasferimento interrotto", m);
                    ui.label(
                        RichText::new(
                            "Questo PC resta in attesa: sul PC vecchio puoi ripetere il \
                             trasferimento, i file già arrivati non vengono ritrasmessi.",
                        )
                        .color(MUTED),
                    );
                    theme::rule(ui);
                }
                self.waiting_ui(ui, port, &mut action);
            }
            JobStatus::Pairing => {
                theme::wait_line(ui, "Un PC si sta collegando: verifica del codice", false);
            }
            JobStatus::Incoming(s) => self.incoming_ui(ui, s, &mut action),
            JobStatus::Transferring => {
                progress_ui(ui, &self.theme, &self.shared.progress());
                theme::rule(ui);
                if theme::button(ui, &self.theme, "Annulla", Kind::Secondary).clicked() {
                    action = Some(|app| app.shared.request_cancel());
                }
            }
            JobStatus::Finished(o) => {
                finished_ui(ui, &self.theme, o, "ricevuti");
                if o.apps.is_some() {
                    theme::rule(ui);
                    apps_ui(ui, &self.theme, o, &self.shared);
                }
                theme::rule(ui);
                if theme::button(ui, &self.theme, "Torna all'inizio", Kind::Secondary).clicked() {
                    action = Some(|app| app.back_home());
                }
            }
            _ => theme::wait_line(ui, "Un momento", false),
        });
        if let Some(f) = action {
            f(self);
        }
        ui.add_space(28.0);
    }

    fn waiting_ui(&self, ui: &mut egui::Ui, port: u16, action: &mut Option<fn(&mut App)>) {
        let pin = self.shared.pin();
        let addresses = if self.ips.is_empty() {
            "nessuna rete rilevata".to_string()
        } else {
            self.ips
                .iter()
                .map(|i| format!("{}:{port}", i.ip))
                .collect::<Vec<_>>()
                .join(" oppure ")
        };
        theme::pin_block(ui, &self.theme, &pin);
        ui.add_space(14.0);
        ui.vertical_centered(|ui| {
            ui.label(
                "Sul PC vecchio apri Transfermon, scegli «PC vecchio», seleziona questo PC e \
                 inserisci il codice.",
            );
            ui.add_space(10.0);
            theme::wait_line(ui, "In attesa del PC vecchio", true);
            ui.add_space(10.0);
            ui.label(
                RichText::new(format!(
                    "Se questo PC non viene trovato da solo, sul PC vecchio scrivi \
                     l'indirizzo: {addresses}"
                ))
                .size(13.0)
                .color(MUTED),
            );
        });
        theme::rule(ui);
        ui.horizontal(|ui| {
            if theme::button(ui, &self.theme, "Indietro", Kind::Secondary).clicked() {
                *action = Some(|app| app.back_home());
            }
            if theme::button(ui, &self.theme, "Nuovo codice", Kind::Secondary).clicked() {
                *action = Some(|app| {
                    app.shared.new_pin();
                });
            }
        });
    }

    fn incoming_ui(&self, ui: &mut egui::Ui, s: &IncomingSummary, action: &mut Option<fn(&mut App)>) {
        ui.label(self.theme.display(
            format!(
                "Il PC \"{}\" (utente {}) vuole trasferire qui i suoi dati.",
                s.peer_name, s.peer_user
            ),
            21.0,
        ));
        ui.add_space(6.0);
        ui.label(format!(
            "{} file in {} cartelle, {} in totale.",
            s.files,
            s.dirs,
            fmt_bytes(s.bytes)
        ));
        if s.skip_files > 0 {
            ui.label(format!(
                "{} file ({}) sono già presenti e identici: non verranno ritrasmessi.",
                s.skip_files,
                fmt_bytes(s.skip_bytes)
            ));
        }
        if s.apps > 0 {
            ui.label(format!(
                "Elenco di {} programmi installati{}.",
                s.apps,
                if s.winget {
                    ", con export winget per reinstallarli"
                } else {
                    ""
                }
            ));
        }
        ui.add_space(10.0);
        ui.label(self.theme.bold("Dove verranno scritti i file"));
        egui::Grid::new("roots_in")
            .num_columns(2)
            .striped(true)
            .spacing([20.0, 6.0])
            .show(ui, |ui| {
                for (r, p) in &s.roots {
                    if *r == Root::Absolute {
                        ui.label("Cartelle aggiuntive");
                        ui.label(self.theme.mono(format!(
                            "stesso percorso del PC vecchio; se il disco qui non esiste: {}",
                            p.display()
                        )));
                    } else {
                        ui.label(r.label());
                        ui.label(self.theme.mono(p.display().to_string()));
                    }
                    ui.end_row();
                }
            });
        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "I file con lo stesso nome vengono sovrascritti. Chiudi i programmi aperti \
                 (browser, Office) prima di accettare, così i loro file di impostazioni non \
                 risultano bloccati.",
            )
            .size(13.0)
            .color(MUTED),
        );
        theme::rule(ui);
        ui.horizontal(|ui| {
            if theme::button_sized(
                ui,
                &self.theme,
                "Accetta e avvia",
                Kind::Primary,
                egui::vec2(180.0, 40.0),
            )
            .clicked()
            {
                *action = Some(|app| app.shared.decide(true));
            }
            if theme::button(ui, &self.theme, "Rifiuta", Kind::Secondary).clicked() {
                *action = Some(|app| app.shared.decide(false));
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let status = self.shared.status();
        let transferring = matches!(status, JobStatus::Transferring);
        root.ctx().request_repaint_after(Duration::from_millis(if transferring {
            100
        } else {
            250
        }));
        if self.ips_at.elapsed() > Duration::from_secs(5) {
            self.ips = sysinfo::local_ipv4s();
            self.ips_at = Instant::now();
        }
        theme::paint_background(root.painter(), root.max_rect());
        self.top_bar(root);
        if self.show_log {
            self.log_panel(root);
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE)
            .show(root, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        column(ui, |ui| match self.screen {
                            Screen::Home => self.home(ui),
                            Screen::SenderSetup => self.sender_setup(ui),
                            Screen::SenderRun => self.sender_run(ui),
                            Screen::Receiver => self.receiver(ui),
                        });
                    });
            });
    }
}

// ----- componenti -----

/// Colonna centrata a larghezza massima, contenuto allineato a sinistra.
fn column(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    let avail = ui.available_width();
    let w = (avail - 48.0).clamp(200.0, COLUMN_WIDTH);
    let side = ((avail - w) / 2.0).max(0.0);
    ui.horizontal_top(|ui| {
        ui.add_space(side);
        ui.vertical(|ui| {
            ui.set_width(w);
            add(ui);
        });
    });
}

fn scan_cell(state: Option<&ScanState>) -> String {
    match state {
        None => "in attesa".to_string(),
        Some(ScanState::Pending) => "calcolo in corso".to_string(),
        Some(ScanState::Done(r)) => format!(
            "{}, {} file{}",
            fmt_bytes(r.bytes),
            r.files.len(),
            if r.errors.is_empty() {
                String::new()
            } else {
                format!(", {} saltati", r.errors.len())
            }
        ),
    }
}

fn progress_ui(ui: &mut egui::Ui, theme: &Theme, p: &Progress) {
    let frac = if p.bytes_total > 0 {
        p.bytes_done as f32 / p.bytes_total as f32
    } else if p.files_total > 0 {
        p.files_done as f32 / p.files_total as f32
    } else {
        0.0
    };
    ui.horizontal(|ui| {
        ui.label(theme.display(format!("{:.0}%", frac * 100.0), 40.0));
        ui.add_space(10.0);
        ui.vertical(|ui| {
            ui.add_space(6.0);
            ui.label(format!(
                "{} di {}, {} di {} file",
                fmt_bytes(p.bytes_done),
                fmt_bytes(p.bytes_total),
                p.files_done,
                p.files_total
            ));
            if let Some(start) = p.started {
                let secs = start.elapsed().as_secs_f64();
                if secs > 0.5 {
                    let speed = p.bytes_done as f64 / secs;
                    let eta = if speed > 0.0 {
                        (p.bytes_total.saturating_sub(p.bytes_done) as f64 / speed) as u64
                    } else {
                        0
                    };
                    ui.label(
                        RichText::new(format!(
                            "{} al secondo, trascorsi {}, mancano circa {}",
                            fmt_bytes(speed as u64),
                            fmt_duration(secs as u64),
                            fmt_duration(eta)
                        ))
                        .color(MUTED),
                    );
                }
            }
        });
    });
    ui.add_space(6.0);
    theme::progress(ui, frac);
    ui.add_space(4.0);
    ui.label(theme.mono(&p.current));
}

fn finished_ui(ui: &mut egui::Ui, theme: &Theme, o: &Outcome, verb: &str) {
    ui.label(
        theme
            .display(
                format!(
                    "Trasferimento completato in {}",
                    fmt_duration(o.elapsed.as_secs())
                ),
                22.0,
            )
            .color(OK),
    );
    ui.label(format!(
        "{} file {verb}, {} in totale.",
        o.files_ok,
        fmt_bytes(o.bytes)
    ));
    if !o.failed.is_empty() {
        ui.add_space(4.0);
        egui::CollapsingHeader::new(format!("{} elementi non trasferiti", o.failed.len())).show(
            ui,
            |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("failed")
                    .max_height(200.0)
                    .show(ui, |ui| {
                        for (p, r) in &o.failed {
                            ui.label(theme.mono(format!("{p}: {r}")));
                        }
                    });
            },
        );
        ui.label(
            RichText::new(
                "Di solito sono file aperti da un programma in esecuzione o senza permessi di \
                 lettura. Chiudi i programmi e ripeti il trasferimento: i file già copiati non \
                 vengono ritrasmessi.",
            )
            .size(13.0)
            .color(MUTED),
        );
    }
}

fn failed_ui(ui: &mut egui::Ui, theme: &Theme, title: &str, message: &str) {
    ui.label(theme.display(title, 22.0).color(ERR));
    ui.label(RichText::new(message).color(INK));
}

fn apps_ui(ui: &mut egui::Ui, theme: &Theme, o: &Outcome, shared: &Shared) {
    let Some(bundle) = &o.apps else {
        return;
    };
    ui.label(theme.display("Programmi del PC vecchio", 19.0));
    ui.label(format!(
        "{} programmi rilevati sul PC \"{}\", {} reinstallabili in automatico con winget.",
        bundle.installed.len(),
        bundle.source_name,
        bundle.winget_count
    ));
    if let Some(saved) = &o.apps_saved {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if let Some(script) = &saved.script {
                if theme::button_sized(
                    ui,
                    theme,
                    "Installa i programmi con winget",
                    Kind::Primary,
                    egui::vec2(240.0, 40.0),
                )
                .clicked()
                {
                    match apps::launch_script(script) {
                        Ok(()) => shared.log("Avviata l'installazione dei programmi con winget"),
                        Err(e) => shared.log(format!("Avvio installazione fallito: {e:#}")),
                    }
                }
            }
            if theme::button(ui, theme, "Apri la cartella con gli elenchi", Kind::Secondary).clicked() {
                if let Err(e) = apps::open_folder(&saved.dir) {
                    shared.log(format!("Apertura cartella fallita: {e:#}"));
                }
            }
        });
        ui.label(theme.mono(format!("Elenco completo: {}", saved.list.display())));
    }
    if bundle.winget_export_json.is_none() {
        ui.label(
            RichText::new(
                "Sul PC vecchio winget non era disponibile: i programmi vanno installati a \
                 mano seguendo l'elenco.",
            )
            .color(MUTED),
        );
    }
    ui.label(
        RichText::new(
            "winget scarica e installa le versioni attuali dei programmi e chiederà le \
             autorizzazioni di Windows. I programmi senza corrispondenza vanno installati a \
             mano. Le impostazioni personali sono già arrivate con la copia di AppData.",
        )
        .size(13.0)
        .color(MUTED),
    );
    ui.add_space(10.0);
    egui::ScrollArea::vertical()
        .id_salt("apps")
        .max_height(300.0)
        .show(ui, |ui| {
            egui::Grid::new("apps_grid")
                .num_columns(4)
                .striped(true)
                .spacing([20.0, 5.0])
                .show(ui, |ui| {
                    ui.label(theme.bold("Programma"));
                    ui.label(theme.bold("Versione"));
                    ui.label(theme.bold("Editore"));
                    ui.label(theme.bold("winget"));
                    ui.end_row();
                    for a in &bundle.installed {
                        ui.label(&a.name);
                        ui.label(RichText::new(&a.version).color(MUTED));
                        ui.label(RichText::new(&a.publisher).color(MUTED));
                        match &a.winget_id {
                            Some(id) => {
                                ui.colored_label(OK, id);
                            }
                            None => {
                                ui.label(RichText::new("da installare a mano").color(MUTED));
                            }
                        }
                        ui.end_row();
                    }
                });
        });
}

fn friendly_error(e: &anyhow::Error) -> String {
    if e.downcast_ref::<BadPin>().is_some() {
        return "Codice di collegamento errato: controlla le 6 cifre mostrate sul PC nuovo.".into();
    }
    if let Some(io) = e.downcast_ref::<std::io::Error>() {
        match io.kind() {
            std::io::ErrorKind::ConnectionRefused => {
                return "Il PC nuovo non accetta connessioni: verifica che sia in modalità «PC nuovo» \
                        e che il firewall consenta Transfermon."
                    .into()
            }
            std::io::ErrorKind::TimedOut => {
                return "Il PC nuovo non risponde (timeout): controlla rete e firewall.".into()
            }
            _ => {}
        }
    }
    format!("{e:#}")
}
