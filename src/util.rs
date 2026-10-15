use std::fs::Metadata;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

/// Formatta i byte in stile italiano ("1,5 GB").
pub fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[i]).replace('.', ",")
    }
}

/// Formatta una durata in secondi come "1 h 02 min", "5 min 03 s", "42 s".
pub fn fmt_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h} h {m:02} min")
    } else if m > 0 {
        format!("{m} min {s:02} s")
    } else {
        format!("{s} s")
    }
}

/// Tempo trascorso da `start` come "hh:mm:ss".
pub fn elapsed_hms(start: Instant) -> String {
    let secs = start.elapsed().as_secs();
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
}

/// Data di modifica in secondi Unix (0 se non disponibile).
pub fn unix_mtime(md: &Metadata) -> i64 {
    filetime::FileTime::from_last_modification_time(md).unix_seconds()
}

/// Secondi Unix correnti.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lock che ignora il poisoning (un thread in panic non deve bloccare l'interfaccia).
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Rende una stringa utilizzabile come nome di file.
pub fn sanitize_filename(s: &str) -> String {
    let out: String = s
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    if out.is_empty() {
        "pc".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_format() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1536), "1,5 KB");
        assert_eq!(fmt_bytes(3 * 1024 * 1024 * 1024), "3,0 GB");
    }

    #[test]
    fn duration_format() {
        assert_eq!(fmt_duration(42), "42 s");
        assert_eq!(fmt_duration(303), "5 min 03 s");
        assert_eq!(fmt_duration(3720), "1 h 02 min");
    }
}
