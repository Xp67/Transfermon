//! Pairing con codice (SPAKE2) e canale cifrato.
//!
//! Il codice a 6 cifre mostrato sul PC nuovo non viaggia mai in rete: i due PC
//! ricavano una chiave di sessione con SPAKE2 (PAKE) e la confermano con un
//! hash. Un codice sbagliato produce chiavi diverse e la conferma fallisce.
//! Dopo il pairing ogni messaggio è un frame `[len u32][ChaCha20-Poly1305]`
//! con nonce = direzione + contatore, quindi niente replay né riordino.

use std::io::{BufReader, BufWriter, Read, Write};
use std::net::TcpStream;

use anyhow::{anyhow, bail, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::protocol::{Msg, MAX_FRAME};

/// Codice di collegamento errato (o l'altro PC non è Transfermon).
#[derive(Debug)]
pub struct BadPin;

impl std::fmt::Display for BadPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("codice di collegamento errato")
    }
}

impl std::error::Error for BadPin {}

const ID_SENDER: &[u8] = b"transfermon-sender";
const ID_RECEIVER: &[u8] = b"transfermon-receiver";
const DIR_S2R: u8 = 1;
const DIR_R2S: u8 = 2;

pub struct SecureStream {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
    cipher: ChaCha20Poly1305,
    send_dir: u8,
    recv_dir: u8,
    send_ctr: u64,
    recv_ctr: u64,
}

impl SecureStream {
    fn new(stream: TcpStream, key: &[u8], send_dir: u8, recv_dir: u8) -> Result<Self> {
        if key.len() != 32 {
            bail!("chiave di sessione di lunghezza inattesa ({})", key.len());
        }
        let reader = BufReader::with_capacity(1 << 20, stream.try_clone()?);
        let writer = BufWriter::with_capacity(1 << 20, stream);
        Ok(Self {
            reader,
            writer,
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            send_dir,
            recv_dir,
            send_ctr: 0,
            recv_ctr: 0,
        })
    }

    pub fn send(&mut self, msg: &Msg) -> Result<()> {
        let plain = bincode::serialize(msg)?;
        let nonce = nonce_for(self.send_dir, self.send_ctr);
        self.send_ctr += 1;
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
            .map_err(|_| anyhow!("cifratura fallita"))?;
        self.writer.write_all(&(ct.len() as u32).to_le_bytes())?;
        self.writer.write_all(&ct)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        Ok(())
    }

    pub fn recv(&mut self) -> Result<Msg> {
        let mut len = [0u8; 4];
        self.reader.read_exact(&mut len)?;
        let len = u32::from_le_bytes(len) as usize;
        if len > MAX_FRAME {
            bail!("pacchetto troppo grande ({len} byte)");
        }
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
        let nonce = nonce_for(self.recv_dir, self.recv_ctr);
        self.recv_ctr += 1;
        let plain = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), buf.as_slice())
            .map_err(|_| anyhow!("pacchetto corrotto o chiave di sessione errata"))?;
        Ok(bincode::deserialize(&plain)?)
    }
}

fn nonce_for(dir: u8, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = dir;
    n[4..].copy_from_slice(&counter.to_le_bytes());
    n
}

fn write_raw(w: &mut TcpStream, data: &[u8]) -> Result<()> {
    let len = u16::try_from(data.len()).map_err(|_| anyhow!("frame di pairing troppo grande"))?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(data)?;
    w.flush()?;
    Ok(())
}

fn read_raw(r: &mut TcpStream) -> Result<Vec<u8>> {
    let mut l = [0u8; 2];
    r.read_exact(&mut l)?;
    let len = u16::from_le_bytes(l) as usize;
    if len > 4096 {
        bail!("frame di pairing troppo grande");
    }
    let mut b = vec![0u8; len];
    r.read_exact(&mut b)?;
    Ok(b)
}

fn confirm_tag(key: &[u8], label: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"transfermon-confirm");
    h.update(key);
    h.update(label);
    h.finalize().to_vec()
}

/// Lato PC vecchio: esegue il pairing e restituisce il canale cifrato.
pub fn pair_sender(mut stream: TcpStream, pin: &str) -> Result<SecureStream> {
    let (state, outbound) = Spake2::<Ed25519Group>::start_a(
        &Password::new(pin.as_bytes()),
        &Identity::new(ID_SENDER),
        &Identity::new(ID_RECEIVER),
    );
    write_raw(&mut stream, &outbound)?;
    let inbound = read_raw(&mut stream)?;
    let key = state
        .finish(&inbound)
        .map_err(|e| anyhow!("scambio chiavi fallito: {e:?}"))?;
    write_raw(&mut stream, &confirm_tag(&key, b"A"))?;
    let status = read_raw(&mut stream)?;
    if status.as_slice() != [1u8] {
        return Err(BadPin.into());
    }
    let tag_b = read_raw(&mut stream)?;
    if tag_b != confirm_tag(&key, b"B") {
        return Err(BadPin.into());
    }
    SecureStream::new(stream, &key, DIR_S2R, DIR_R2S)
}

/// Lato PC nuovo: esegue il pairing e restituisce il canale cifrato.
pub fn pair_receiver(mut stream: TcpStream, pin: &str) -> Result<SecureStream> {
    let (state, outbound) = Spake2::<Ed25519Group>::start_b(
        &Password::new(pin.as_bytes()),
        &Identity::new(ID_SENDER),
        &Identity::new(ID_RECEIVER),
    );
    let inbound = read_raw(&mut stream)?;
    write_raw(&mut stream, &outbound)?;
    let key = state
        .finish(&inbound)
        .map_err(|e| anyhow!("scambio chiavi fallito: {e:?}"))?;
    let tag_a = read_raw(&mut stream)?;
    if tag_a != confirm_tag(&key, b"A") {
        let _ = write_raw(&mut stream, &[0u8]);
        return Err(BadPin.into());
    }
    write_raw(&mut stream, &[1u8])?;
    write_raw(&mut stream, &confirm_tag(&key, b"B"))?;
    SecureStream::new(stream, &key, DIR_R2S, DIR_S2R)
}
