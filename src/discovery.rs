//! Ricerca delle altre copie di Transfermon sulla rete locale.
//!
//! Ogni istanza manda un beacon UDP ogni secondo in broadcast (limitato e
//! diretto su ogni interfaccia) sulla porta 47831 e ascolta quelli altrui.
//! Il socket usa SO_REUSEADDR, così due istanze sullo stesso PC convivono.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::protocol::{Beacon, Role, MAGIC, PROTOCOL_VERSION};
use crate::shared::Shared;
use crate::sysinfo;
use crate::util::lock;

pub const DISCOVERY_PORT: u16 = 47831;
const PEER_TTL: Duration = Duration::from_secs(6);
const BEACON_EVERY: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub struct Peer {
    pub id: u64,
    pub name: String,
    pub user: String,
    pub role: Role,
    pub ip: IpAddr,
    pub tcp_port: u16,
    pub version: u16,
    pub last_seen: Instant,
}

fn open_socket() -> std::io::Result<UdpSocket> {
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_broadcast(true)?;
    s.bind(&SockAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT)))?;
    s.set_read_timeout(Some(Duration::from_millis(300)))?;
    Ok(s.into())
}

/// Avvia il thread di discovery; gira finché `shared.shutdown` non è impostato.
pub fn spawn(shared: Arc<Shared>) -> JoinHandle<()> {
    thread::spawn(move || {
        let sock = match open_socket() {
            Ok(s) => s,
            Err(e) => {
                shared.log(format!(
                    "Ricerca automatica in rete non disponibile ({e}). Usa l'indirizzo manuale."
                ));
                return;
            }
        };
        let mut last_beacon = Instant::now() - BEACON_EVERY;
        let mut buf = [0u8; 2048];
        loop {
            if shared.shutdown.load(Ordering::Relaxed) {
                break;
            }
            if last_beacon.elapsed() >= BEACON_EVERY {
                send_beacon(&sock, &shared);
                last_beacon = Instant::now();
            }
            match sock.recv_from(&mut buf) {
                Ok((n, from)) => {
                    if let Ok(b) = bincode::deserialize::<Beacon>(&buf[..n]) {
                        if b.magic == MAGIC && b.id != shared.my_id {
                            upsert_peer(&shared, b, from.ip());
                        }
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => thread::sleep(Duration::from_millis(200)),
            }
            lock(&shared.peers).retain(|p| p.last_seen.elapsed() < PEER_TTL);
        }
    })
}

fn send_beacon(sock: &UdpSocket, shared: &Shared) {
    let beacon = Beacon {
        magic: MAGIC,
        version: PROTOCOL_VERSION,
        id: shared.my_id,
        name: shared.my_name.clone(),
        user: shared.my_user.clone(),
        role: shared.role(),
        tcp_port: shared.tcp_port.load(Ordering::Relaxed),
    };
    let Ok(bytes) = bincode::serialize(&beacon) else {
        return;
    };
    let mut targets = vec![Ipv4Addr::BROADCAST];
    for ip in sysinfo::local_ipv4s() {
        if let Some(b) = ip.broadcast {
            if !targets.contains(&b) {
                targets.push(b);
            }
        }
    }
    for t in targets {
        let _ = sock.send_to(&bytes, (t, DISCOVERY_PORT));
    }
}

fn upsert_peer(shared: &Shared, b: Beacon, ip: IpAddr) {
    let mut peers = lock(&shared.peers);
    let now = Instant::now();
    if let Some(p) = peers.iter_mut().find(|p| p.id == b.id) {
        p.name = b.name;
        p.user = b.user;
        p.role = b.role;
        p.ip = ip;
        p.tcp_port = b.tcp_port;
        p.version = b.version;
        p.last_seen = now;
    } else {
        shared.log(format!("Trovato in rete: {} ({}) su {}", b.name, b.user, ip));
        peers.push(Peer {
            id: b.id,
            name: b.name,
            user: b.user,
            role: b.role,
            ip,
            tcp_port: b.tcp_port,
            version: b.version,
            last_seen: now,
        });
    }
    peers.sort_by_key(|p| p.name.to_lowercase());
}
