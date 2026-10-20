//! Trasferimento completo fra due istanze in-process (senza interfaccia).

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;

use transfermon::dest::DestMap;
use transfermon::protocol::{AppsBundle, InstalledApp, Root};
use transfermon::scan;
use transfermon::secure::BadPin;
use transfermon::shared::Shared;
use transfermon::sysinfo::KnownFolders;
use transfermon::transfer::{self, Plan};
use transfermon::util;

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("transfermon-rt-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Dove `DestMap::for_test` fa atterrare una cartella aggiuntiva.
fn dest_of_absolute(dst: &Path, src: &Path) -> PathBuf {
    let s = src.to_string_lossy().to_string();
    let drive = s.chars().next().unwrap().to_ascii_uppercase();
    dst.join("dischi")
        .join(format!("Disco_{drive}"))
        .join(s[3..].trim_start_matches(['\\', '/']))
}

fn run_pair(
    plan: Plan,
    sender_pin: &str,
    receiver_pin: &str,
    dst: &Path,
) -> (anyhow::Result<transfermon::shared::Outcome>, anyhow::Result<transfermon::shared::Outcome>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let dest = DestMap::for_test(dst);
    let rpin = receiver_pin.to_string();
    let receiver = thread::spawn(move || {
        let shared = Shared::new(false);
        let (s, _) = listener.accept().unwrap();
        transfer::run_receiver(s, &rpin, &dest, &shared, &mut |_| true)
    });
    let shared = Shared::new(false);
    let sent = transfer::run_sender(addr, sender_pin, &plan, &shared);
    let received = receiver.join().unwrap();
    (sent, received)
}

#[test]
fn roundtrip_copies_tree_and_skips_identical_files_on_rerun() {
    let base = tmp("tree");
    let src = base.join("src");
    let dst = base.join("dst");
    fs::create_dir_all(src.join("a").join("b")).unwrap();
    fs::create_dir_all(src.join("vuota")).unwrap();
    fs::write(src.join("a").join("uno.txt"), b"ciao").unwrap();
    fs::write(src.join("a").join("b").join("vuoto.bin"), b"").unwrap();
    let big: Vec<u8> = (0..3_000_000u32).map(|i| (i % 251) as u8).collect();
    fs::write(src.join("grande.bin"), &big).unwrap();

    // anche una radice nota (Documenti), mappata sulla finta home di destinazione
    let kf_src = KnownFolders::under(&base.join("srchome"));
    fs::create_dir_all(kf_src.documents.join("Lavoro")).unwrap();
    fs::write(kf_src.documents.join("Lavoro").join("doc.txt"), b"documento").unwrap();

    let cancel = AtomicBool::new(false);
    let extra = scan::scan(Root::Absolute, &src, &kf_src, &cancel);
    assert_eq!(extra.files.len(), 3);
    assert_eq!(extra.bytes, 4 + big.len() as u64);
    let docs = scan::scan(Root::Documents, &kf_src.documents, &kf_src, &cancel);
    assert_eq!(docs.files.len(), 1);

    let apps = AppsBundle {
        source_name: "VECCHIO".into(),
        installed: vec![InstalledApp {
            name: "Prova".into(),
            version: "1.0".into(),
            ..Default::default()
        }],
        winget_export_json: Some("{}".into()),
        winget_count: 0,
        winget_notes: vec![],
    };
    let plan = Plan {
        scans: vec![Arc::new(extra), Arc::new(docs)],
        apps: Some(apps.clone()),
    };
    let (sent, received) = run_pair(plan, "123456", "123456", &dst);
    let sent = sent.expect("invio");
    let received = received.expect("ricezione");
    assert_eq!(sent.files_ok, 4);
    assert_eq!(received.files_ok, 4);
    assert!(sent.failed.is_empty(), "{:?}", sent.failed);
    assert!(received.failed.is_empty(), "{:?}", received.failed);
    assert_eq!(received.apps, Some(apps));

    let d = dest_of_absolute(&dst, &src);
    assert_eq!(fs::read(d.join("a").join("uno.txt")).unwrap(), b"ciao");
    assert_eq!(fs::read(d.join("grande.bin")).unwrap(), big);
    assert!(d.join("vuota").is_dir());
    assert_eq!(fs::metadata(d.join("a").join("b").join("vuoto.bin")).unwrap().len(), 0);
    let dest_docs = DestMap::for_test(&dst).known_folders().documents.clone();
    assert_eq!(
        fs::read(dest_docs.join("Lavoro").join("doc.txt")).unwrap(),
        b"documento"
    );
    // la data di modifica viene conservata
    let m_src = util::unix_mtime(&fs::metadata(src.join("grande.bin")).unwrap());
    let m_dst = util::unix_mtime(&fs::metadata(d.join("grande.bin")).unwrap());
    assert_eq!(m_src, m_dst);

    // seconda esecuzione: tutto identico, niente da ritrasmettere
    let extra2 = scan::scan(Root::Absolute, &src, &kf_src, &cancel);
    let docs2 = scan::scan(Root::Documents, &kf_src.documents, &kf_src, &cancel);
    let plan2 = Plan {
        scans: vec![Arc::new(extra2), Arc::new(docs2)],
        apps: None,
    };
    let (sent2, received2) = run_pair(plan2, "123456", "123456", &dst);
    assert_eq!(sent2.expect("invio 2").files_ok, 0);
    assert_eq!(received2.expect("ricezione 2").files_ok, 0);

    let _ = fs::remove_dir_all(&base);
}

/// Elenchi più lunghi di un blocco (`MANIFEST_BATCH`): l'elenco viaggia a
/// pezzi e il bitset dei file da saltare copre tutti gli indici.
#[test]
fn many_files_cross_manifest_batches_and_skip_on_rerun() {
    let base = tmp("many");
    let src = base.join("src");
    let dst = base.join("dst");
    const N: usize = 2 * transfermon::protocol::MANIFEST_BATCH + 321;
    for i in 0..N {
        let dir = src.join(format!("d{}", i % 7));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!("f{i}.txt")), format!("{i}")).unwrap();
    }
    let kf = KnownFolders::under(&base);
    let cancel = AtomicBool::new(false);
    let s = scan::scan(Root::Absolute, &src, &kf, &cancel);
    assert_eq!(s.files.len(), N);
    let plan = Plan {
        scans: vec![Arc::new(s)],
        apps: None,
    };
    let (sent, received) = run_pair(plan, "654321", "654321", &dst);
    assert_eq!(sent.expect("invio").files_ok as usize, N);
    let received = received.expect("ricezione");
    assert_eq!(received.files_ok as usize, N);
    assert!(received.failed.is_empty(), "{:?}", &received.failed[..received.failed.len().min(5)]);
    let d = dest_of_absolute(&dst, &src);
    // l'ultimo file è f4320 e 4320 % 7 == 1
    assert_eq!(fs::read(d.join("d1").join("f4320.txt")).unwrap(), b"4320");

    let s2 = scan::scan(Root::Absolute, &src, &kf, &cancel);
    let plan2 = Plan {
        scans: vec![Arc::new(s2)],
        apps: None,
    };
    let (sent2, received2) = run_pair(plan2, "654321", "654321", &dst);
    assert_eq!(sent2.expect("invio 2").files_ok, 0);
    assert_eq!(received2.expect("ricezione 2").files_ok, 0);
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn wrong_pin_is_rejected_on_both_sides() {
    let base = tmp("pin");
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
    let (sent, received) = run_pair(plan, "111111", "222222", &dst);
    let se = sent.expect_err("il mittente deve fallire");
    assert!(se.downcast_ref::<BadPin>().is_some(), "{se:#}");
    let re = received.expect_err("il destinatario deve fallire");
    assert!(re.downcast_ref::<BadPin>().is_some(), "{re:#}");
    assert!(!dest_of_absolute(&dst, &src).join("x.txt").exists());
    let _ = fs::remove_dir_all(&base);
}
