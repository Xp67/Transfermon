//! Il listener del PC nuovo (`receiver_service`) con un mittente reale:
//! pairing col codice generato, decisione dell'utente, esito in `JobStatus`.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use transfermon::dest::DestMap;
use transfermon::protocol::{Role, Root};
use transfermon::receiver_service;
use transfermon::scan;
use transfermon::shared::{JobStatus, Shared};
use transfermon::sysinfo::KnownFolders;
use transfermon::transfer::{self, Plan};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("transfermon-svc-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn wait_status(shared: &Shared, pred: impl Fn(&JobStatus) -> bool) -> JobStatus {
    let start = Instant::now();
    loop {
        let s = shared.status();
        if pred(&s) {
            return s;
        }
        if let JobStatus::Failed(e) = &s {
            panic!("ricezione fallita: {e}");
        }
        assert!(start.elapsed() < Duration::from_secs(15), "timeout; stato: {s:?}");
        thread::sleep(Duration::from_millis(30));
    }
}

#[test]
fn service_pairs_with_generated_pin_and_reports_outcome() {
    let base = tmp("ok");
    let src = base.join("src");
    let dst = base.join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("nota.txt"), b"contenuto").unwrap();
    let kf = KnownFolders::under(&base);
    let s = scan::scan(Root::Absolute, &src, &kf, &AtomicBool::new(false));
    let plan = Plan {
        scans: vec![Arc::new(s)],
        apps: None,
    };

    let shared = Arc::new(Shared::new(false));
    let svc = receiver_service::start(Arc::clone(&shared), DestMap::for_test(&dst)).unwrap();
    assert_eq!(shared.role(), Role::Receiver);
    let pin = shared.pin();
    assert_eq!(pin.len(), 6);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), svc.addr.port());

    let sender = thread::spawn(move || {
        let s = Shared::new(false);
        transfer::run_sender(addr, &pin, &plan, &s)
    });

    wait_status(&shared, |s| matches!(s, JobStatus::Incoming(_)));
    shared.decide(true);
    let sent = sender.join().unwrap().expect("invio");
    assert_eq!(sent.files_ok, 1);
    let finished = wait_status(&shared, |s| matches!(s, JobStatus::Finished(_)));
    let JobStatus::Finished(o) = finished else {
        unreachable!()
    };
    assert_eq!(o.files_ok, 1);
    assert!(o.failed.is_empty());
    drop(svc);
    assert_eq!(shared.role(), Role::Idle);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn service_rejects_wrong_pin_and_keeps_listening() {
    let base = tmp("badpin");
    let src = base.join("src");
    let dst = base.join("dst");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("x.txt"), b"x").unwrap();
    let kf = KnownFolders::under(&base);
    let s = scan::scan(Root::Absolute, &src, &kf, &AtomicBool::new(false));
    let plan = Plan {
        scans: vec![Arc::new(s)],
        apps: None,
    };

    let shared = Arc::new(Shared::new(false));
    let svc = receiver_service::start(Arc::clone(&shared), DestMap::for_test(&dst)).unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), svc.addr.port());
    let s = Shared::new(false);
    let err = transfer::run_sender(addr, "000000", &plan, &s).expect_err("codice sbagliato");
    assert!(err.downcast_ref::<transfermon::secure::BadPin>().is_some(), "{err:#}");

    // il servizio è ancora in ascolto: col codice giusto il trasferimento va a buon fine
    let pin = shared.pin();
    let sender = thread::spawn(move || {
        let s = Shared::new(false);
        transfer::run_sender(addr, &pin, &plan, &s)
    });
    wait_status(&shared, |s| matches!(s, JobStatus::Incoming(_)));
    shared.decide(true);
    assert_eq!(sender.join().unwrap().expect("invio").files_ok, 1);
    wait_status(&shared, |s| matches!(s, JobStatus::Finished(_)));
    drop(svc);
    let _ = fs::remove_dir_all(&base);
}
