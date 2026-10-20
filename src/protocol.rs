//! Messaggi scambiati fra PC vecchio (mittente) e PC nuovo (destinatario).
//!
//! Tutti i messaggi viaggiano dentro frame cifrati (vedi `secure`), serializzati
//! con bincode. Il protocollo è a turni: dopo il pairing il mittente manda
//! `Hello`, riceve `Hello`, manda `Manifest`, riceve `Accept`/`Reject`, poi
//! streamma i file (`FileData`/`FileDone`/`FileFailed`), chiude con `Finished`
//! e aspetta `Ack`.

use serde::{Deserialize, Serialize};

/// Versione del protocollo: deve coincidere sui due PC.
pub const PROTOCOL_VERSION: u16 = 2;
/// Dimensione massima di un frame cifrato accettato in lettura.
pub const MAX_FRAME: usize = 8 * 1024 * 1024;
/// Voci dell'elenco per pacchetto (2000 percorsi anche lunghi stanno in ~1 MB).
pub const MANIFEST_BATCH: usize = 2000;
/// Dimensione dei blocchi in cui vengono spezzati i file.
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// Firma dei beacon UDP.
pub const MAGIC: [u8; 8] = *b"TRNSFMON";

/// Radice logica di un percorso: il PC nuovo la risolve nella propria cartella
/// corrispondente (il profilo utente può avere nome diverso).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum Root {
    Desktop,
    Documents,
    Downloads,
    Pictures,
    Music,
    Videos,
    /// Il resto della cartella utente (.ssh, .gitconfig, Preferiti, progetti...).
    Home,
    /// `AppData\Roaming`: impostazioni delle applicazioni.
    Roaming,
    /// `AppData\Local`: dati locali delle applicazioni (cache escluse).
    Local,
    /// Cartella scelta a mano: `rel` contiene il percorso assoluto completo.
    #[default]
    Absolute,
}

impl Root {
    /// Le radici note, nell'ordine in cui vengono mostrate.
    pub const KNOWN: [Root; 9] = [
        Root::Desktop,
        Root::Documents,
        Root::Downloads,
        Root::Pictures,
        Root::Music,
        Root::Videos,
        Root::Home,
        Root::Roaming,
        Root::Local,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Root::Desktop => "Desktop",
            Root::Documents => "Documenti",
            Root::Downloads => "Download",
            Root::Pictures => "Immagini",
            Root::Music => "Musica",
            Root::Videos => "Video",
            Root::Home => "Altri file del profilo",
            Root::Roaming => "Impostazioni delle app",
            Root::Local => "Dati locali delle app",
            Root::Absolute => "Cartella aggiuntiva",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Root::Desktop => "I file e i collegamenti sul desktop.",
            Root::Documents => "La cartella Documenti.",
            Root::Downloads => "La cartella Download.",
            Root::Pictures => "La cartella Immagini.",
            Root::Music => "La cartella Musica.",
            Root::Videos => "La cartella Video.",
            Root::Home => {
                "Tutto il resto della cartella utente (C:\\Users\\<nome>): .ssh, .gitconfig, Preferiti, \
                 Contatti, Giochi salvati, progetti... Esclusi: OneDrive, AppData, i file di sistema \
                 NTUSER, Docker, le cache di Rust/NuGet/Gradle."
            }
            Root::Roaming => {
                "AppData\\Roaming: i profili e le preferenze che i programmi salvano per l'utente \
                 (browser, Office, Discord, Thunderbird...)."
            }
            Root::Local => {
                "AppData\\Local: dati più voluminosi delle app (Chrome/Edge, VS Code, programmi \
                 installati solo per l'utente). Cache, file temporanei, Docker e le app dello Store \
                 vengono esclusi automaticamente."
            }
            Root::Absolute => "Cartella scelta a mano: sul PC nuovo finisce nello stesso percorso.",
        }
    }

    /// Selezionata di default nell'interfaccia?
    pub fn default_on(self) -> bool {
        !matches!(self, Root::Local | Root::Absolute)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub root: Root,
    /// Percorso relativo alla radice (o assoluto per `Root::Absolute`), con `\`.
    pub rel: String,
    pub size: u64,
    /// Data di modifica in secondi Unix.
    pub mtime: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub root: Root,
    pub rel: String,
}

/// Un programma trovato nel registro di Windows sul PC vecchio.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct InstalledApp {
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub install_location: String,
    /// Identificativo winget stimato (se trovato nell'export).
    pub winget_id: Option<String>,
}

/// Elenco programmi + export winget, inviato in coda al trasferimento.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct AppsBundle {
    pub source_name: String,
    pub installed: Vec<InstalledApp>,
    /// Contenuto del file prodotto da `winget export` (se winget è disponibile).
    pub winget_export_json: Option<String>,
    /// Numero di pacchetti nell'export winget.
    pub winget_count: usize,
    /// Righe stampate da winget durante l'export (pacchetti non disponibili ecc.).
    pub winget_notes: Vec<String>,
}

/// Elenco completo di ciò che viene trasferito. Non viaggia mai in un unico
/// pacchetto: con centinaia di migliaia di file supererebbe `MAX_FRAME`.
/// Il mittente manda `ManifestStart`, poi `ManifestDirs`/`ManifestFiles` a
/// blocchi di `MANIFEST_BATCH` voci, poi `ManifestEnd`; il destinatario lo
/// ricompone.
#[derive(Clone, Debug, Default)]
pub struct Manifest {
    pub roots: Vec<Root>,
    pub dirs: Vec<DirEntry>,
    pub files: Vec<FileEntry>,
    pub total_bytes: u64,
    pub apps: Option<AppsBundle>,
}

/// Intestazione dell'elenco: i totali dichiarati e l'elenco programmi.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ManifestHead {
    pub roots: Vec<Root>,
    pub dirs: u64,
    pub files: u64,
    pub total_bytes: u64,
    pub apps: Option<AppsBundle>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Msg {
    Hello { name: String, user: String, version: u16 },
    ManifestStart(ManifestHead),
    ManifestDirs(Vec<DirEntry>),
    ManifestFiles(Vec<FileEntry>),
    ManifestEnd,
    /// Il PC nuovo accetta; `skip` è un bitset (un bit per file, nell'ordine
    /// dell'elenco, bit meno significativo per primo) dei file già identici.
    Accept { skip: Vec<u8> },
    Reject,
    FileData { index: u32, offset: u64, data: Vec<u8> },
    FileDone { index: u32 },
    FileFailed { index: u32, reason: String },
    Finished,
    Ack { files_ok: u64, failed: u32 },
    Error(String),
}

impl Msg {
    /// Nome breve, per i messaggi di errore (senza stampare i dati).
    pub fn kind(&self) -> &'static str {
        match self {
            Msg::Hello { .. } => "Hello",
            Msg::ManifestStart(_) => "ManifestStart",
            Msg::ManifestDirs(_) => "ManifestDirs",
            Msg::ManifestFiles(_) => "ManifestFiles",
            Msg::ManifestEnd => "ManifestEnd",
            Msg::Accept { .. } => "Accept",
            Msg::Reject => "Reject",
            Msg::FileData { .. } => "FileData",
            Msg::FileDone { .. } => "FileDone",
            Msg::FileFailed { .. } => "FileFailed",
            Msg::Finished => "Finished",
            Msg::Ack { .. } => "Ack",
            Msg::Error(_) => "Error",
        }
    }
}

/// Bitset di `n` bit, tutti a zero.
pub fn bitset_new(n: usize) -> Vec<u8> {
    vec![0u8; n.div_ceil(8)]
}

pub fn bitset_set(bits: &mut [u8], i: usize) {
    if let Some(b) = bits.get_mut(i / 8) {
        *b |= 1 << (i % 8);
    }
}

pub fn bitset_get(bits: &[u8], i: usize) -> bool {
    bits.get(i / 8).map(|b| b & (1 << (i % 8)) != 0).unwrap_or(false)
}

pub fn bitset_count(bits: &[u8]) -> usize {
    bits.iter().map(|b| b.count_ones() as usize).sum()
}

/// Ruolo annunciato nei beacon di rete.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    Idle,
    Sender,
    Receiver,
}

impl Role {
    pub fn label(self) -> &'static str {
        match self {
            Role::Idle => "avviato, nessun ruolo scelto",
            Role::Sender => "PC vecchio (invia)",
            Role::Receiver => "PC nuovo (pronto a ricevere)",
        }
    }
}

/// Pacchetto UDP di presenza.
#[derive(Serialize, Deserialize, Debug)]
pub struct Beacon {
    pub magic: [u8; 8],
    pub version: u16,
    pub id: u64,
    pub name: String,
    pub user: String,
    pub role: Role,
    pub tcp_port: u16,
}
