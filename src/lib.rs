//! Transfermon: libreria condivisa fra l'interfaccia grafica e i test.
//!
//! Moduli:
//! - `discovery`: ricerca delle altre copie di Transfermon sulla LAN (beacon UDP).
//! - `secure`: pairing con codice (SPAKE2) e canale cifrato (ChaCha20-Poly1305).
//! - `protocol`: messaggi scambiati fra PC vecchio e PC nuovo.
//! - `scan`: scansione delle cartelle del profilo utente con le esclusioni.
//! - `dest`: mappatura dei percorsi sul PC nuovo.
//! - `transfer`: motore di invio/ricezione.
//! - `apps`: elenco programmi installati (registro) e export/import winget.
//! - `receiver_service`: listener TCP del PC nuovo.
//! - `shared`: stato condiviso fra thread e interfaccia.

pub mod apps;
pub mod dest;
pub mod discovery;
pub mod protocol;
pub mod receiver_service;
pub mod scan;
pub mod secure;
pub mod shared;
pub mod sysinfo;
pub mod transfer;
pub mod util;
