//! Key-less payload recovery: cryptanalysis for decryptors whose key is
//! not an immediate operand.
//!
//! A decryptor that holds its key in a register (`xor [rsi], al` with
//! `rax` loaded elsewhere and rotated each byte) gives a static reader
//! nothing to pluck. But the ciphers such stubs use are weak. The
//! detector already knows the loop's operation (xor / add / sub); a
//! repeating key of period L under that operation is L independent
//! single-byte problems (the classic Vigenère attack), so this module
//! solves for the key from the ciphertext alone:
//!
//! - for each period 1..=[`MAX_PERIOD`], split the region into columns and
//!   pick, per column, the key byte that makes the column most text-like
//!   (scored from a byte histogram, so O(256²) per column whatever the
//!   region size);
//! - judge each candidate by the **letters** it puts inside readable runs,
//!   and keep the shortest period within 3% of the best (longer periods
//!   overfit by a few letters);
//! - accept only a clear win (see [`solve`]), which keeps already-plain
//!   data and random noise from "recovering" anything.

use crate::detect::Operation;

/// Shortest printable run counted as a string.
pub const MIN_RUN: usize = 6;
/// Longest repeating-key period tried.
pub const MAX_PERIOD: usize = 16;
/// Bytes of the region used to solve the key (the key then decrypts the
/// whole region). Plenty for statistics, bounded for speed.
pub const SOLVE_WINDOW: usize = 64 * 1024;
/// A recovered key must produce a readable run at least this long that is
/// mostly letters and spaces. Noise optimized per column tops out around
/// 10; real payload strings run far longer.
pub const MIN_TEXT_RUN: usize = 16;

/// A key recovered by cryptanalysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SolvedKey {
    pub op: Operation,
    /// The repeating key, in decryption order.
    pub key: Vec<u8>,
    /// Letters inside readable runs after decryption (solve window).
    pub letters: usize,
    /// The same measure on the undecrypted window.
    pub baseline_letters: usize,
}

/// How much a byte value looks like plaintext (column scoring).
fn weight(b: u8) -> u32 {
    match b {
        b'a'..=b'z' | b'A'..=b'Z' | b' ' => 3,
        b'0'..=b'9' | b'.' | b',' | b'/' | b':' | b'_' | b'-' | b'\n' => 2,
        0x21..=0x7e | b'\t' | b'\r' => 1,
        _ => 0,
    }
}

fn is_printable(b: u8) -> bool {
    (0x20..=0x7e).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

fn is_letter(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b' '
}

/// Text statistics of a buffer: letters inside readable runs of at least
/// [`MIN_RUN`], and the longest such run that is at least 60% letters.
pub fn text_stats(buf: &[u8]) -> (usize, usize) {
    let (mut letters, mut longest) = (0, 0);
    let mut flush = |start: usize, end: usize| {
        let run = &buf[start..end];
        if run.len() >= MIN_RUN {
            let l = run.iter().filter(|&&b| is_letter(b)).count();
            letters += l;
            if l * 10 >= run.len() * 6 {
                longest = longest.max(run.len());
            }
        }
    };
    let mut start = 0;
    for (i, &b) in buf.iter().enumerate() {
        if !is_printable(b) {
            flush(start, i);
            start = i + 1;
        }
    }
    flush(start, buf.len());
    (letters, longest)
}

/// Run the decryptor operation forward with a repeating key, as the stub
/// itself would: `xor`/`add`/`sub` each byte with the next key byte.
pub fn decrypt(buf: &[u8], op: Operation, key: &[u8]) -> Vec<u8> {
    buf.iter()
        .enumerate()
        .map(|(i, &c)| apply(c, op, key[i % key.len()]))
        .collect()
}

fn apply(c: u8, op: Operation, k: u8) -> u8 {
    match op {
        Operation::Xor => c ^ k,
        Operation::Add => c.wrapping_add(k),
        Operation::Sub => c.wrapping_sub(k),
    }
}

/// The key byte that makes a column (as a byte histogram) most text-like.
fn best_column_key(hist: &[u32; 256], op: Operation) -> u8 {
    let mut best = (0u8, 0u64);
    for k in 0..=255u8 {
        let score: u64 = hist
            .iter()
            .enumerate()
            .filter(|(_, &n)| n > 0)
            .map(|(c, &n)| n as u64 * weight(apply(c as u8, op, k)) as u64)
            .sum();
        if score > best.1 {
            best = (k, score);
        }
    }
    best.0
}

fn column_histogram(window: &[u8], offset: usize, period: usize) -> [u32; 256] {
    let mut h = [0u32; 256];
    for &b in window.iter().skip(offset).step_by(period) {
        h[b as usize] += 1;
    }
    h
}

/// Collapse a key that repeats a shorter period (`abab` → `ab`).
fn minimal_period(key: &[u8]) -> Vec<u8> {
    for p in 1..key.len() {
        if key.len() % p == 0 && key.iter().enumerate().all(|(i, &b)| b == key[i % p]) {
            return key[..p].to_vec();
        }
    }
    key.to_vec()
}

/// Solve for the repeating key that `op` decrypts `region` with.
///
/// Returns `None` unless the best decryption clearly gains letters over the
/// undecrypted bytes (at least 1.1× plus 24; weak keys of small bytes leave
/// ciphertext half-readable, so the gain can be modest) *and* contains a
/// letter-rich readable run of at least [`MIN_TEXT_RUN`] characters. A
/// window that is already at least half letters is not ciphertext and is
/// declined outright; per-column overfitting of noise never produces such
/// runs. The analyzer additionally only calls this when a decryptor loop
/// was detected.
pub fn solve(region: &[u8], op: Operation) -> Option<SolvedKey> {
    let window = &region[..region.len().min(SOLVE_WINDOW)];
    if window.len() < 32 {
        return None;
    }
    let (baseline_letters, _) = text_stats(window);
    // Mostly-readable bytes are not an encrypted payload. Without this,
    // highly repetitive text lets a long period remap each column's few
    // distinct bytes onto letters and "gain" gibberish.
    if baseline_letters * 2 >= window.len() {
        return None;
    }

    let mut scored: Vec<(Vec<u8>, usize, usize)> = Vec::new();
    for period in 1..=MAX_PERIOD.min(window.len() / 8) {
        let key = minimal_period(
            &(0..period)
                .map(|j| best_column_key(&column_histogram(window, j, period), op))
                .collect::<Vec<u8>>(),
        );
        if key.iter().all(|&k| k == 0) || scored.iter().any(|(k, _, _)| *k == key) {
            continue; // identity, or a period we already scored
        }
        let (letters, longest) = text_stats(&decrypt(window, op, &key));
        scored.push((key, letters, longest));
    }

    let max = scored.iter().map(|s| s.1).max()?;
    // Shortest period within 3% of the best: longer periods overfit.
    let (key, letters, longest) = scored.into_iter().find(|s| s.1 * 100 >= max * 97)?;
    (letters * 10 >= baseline_letters * 11 + 240 && longest >= MIN_TEXT_RUN).then_some(SolvedKey {
        op,
        key,
        letters,
        baseline_letters,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Random padding sprinkled with readable strings, like a real payload.
    fn payload(seed: u64, len: usize) -> Vec<u8> {
        let strings: [&[u8]; 4] = [
            b"GET /beacon HTTP/1.1\r\nHost: c2.example\r\n",
            b"User-Agent: Mozilla/5.0 (Windows NT 10.0)\n",
            b"cmd.exe /c whoami && ipconfig /all\n",
            b"This is a hidden message in the payload.\n",
        ];
        let mut state = seed | 1;
        let mut out = Vec::new();
        let mut i = 0;
        while out.len() < len {
            for _ in 0..48 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                out.push((state >> 24) as u8);
            }
            out.extend_from_slice(strings[i % strings.len()]);
            i += 1;
        }
        out.truncate(len);
        out
    }

    /// Encrypt so that running `op` with `key` decrypts.
    fn encrypt(plain: &[u8], op: Operation, key: &[u8]) -> Vec<u8> {
        let inverse = match op {
            Operation::Xor => Operation::Xor,
            Operation::Add => Operation::Sub,
            Operation::Sub => Operation::Add,
        };
        decrypt(plain, inverse, key)
    }

    #[test]
    fn recovers_repeating_xor_keys_of_many_lengths() {
        for key in [
            &[0x42u8][..],
            &[0xde, 0xad],
            &[0x13, 0x37, 0xc0],
            &[0xde, 0x4d, 0xbe, 0xef],
            &[1, 2, 3, 4, 5, 6, 7],
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        ] {
            let plain = payload(key.len() as u64 * 7919, 1024);
            let solved = solve(&encrypt(&plain, Operation::Xor, key), Operation::Xor)
                .unwrap_or_else(|| panic!("no key for {key:02x?}"));
            assert_eq!(solved.key, key, "wrong key for {key:02x?}");
            assert!(solved.letters > solved.baseline_letters);
        }
    }

    #[test]
    fn recovers_add_and_sub_keys() {
        let plain = payload(99, 1024);
        for (op, key) in [
            (Operation::Add, &[0x37u8][..]),
            (Operation::Sub, &[0x91u8][..]),
            (Operation::Add, &[0x10, 0x20, 0x30]),
        ] {
            let s = solve(&encrypt(&plain, op, key), op).expect("solved");
            assert_eq!(s.key, key, "{op:?}");
            assert_eq!(decrypt(&encrypt(&plain, op, key), op, &s.key), plain);
        }
    }

    #[test]
    fn plain_or_random_data_recovers_nothing() {
        let text =
            b"Usage: ls [OPTION]... [FILE]...\nList information about the FILEs.\n".repeat(20);
        for op in [Operation::Xor, Operation::Add, Operation::Sub] {
            assert!(solve(&text, op).is_none(), "plain text, {op:?}");
        }
        let mut state = 0x9e3779b97f4a7c15u64;
        let noise: Vec<u8> = (0..4096)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect();
        for op in [Operation::Xor, Operation::Add, Operation::Sub] {
            assert!(solve(&noise, op).is_none(), "noise, {op:?}");
        }
        assert!(solve(b"short", Operation::Xor).is_none());
    }

    #[test]
    fn text_stats_counts_letters_in_long_runs() {
        assert_eq!(text_stats(b"\x00abc\x00abcdef\x00"), (6, 6));
        assert_eq!(text_stats(b"!!!!!!!!"), (0, 0));
        assert_eq!(text_stats(b"\x01\x02"), (0, 0));
    }

    #[test]
    fn minimal_period_collapses_repeats() {
        assert_eq!(minimal_period(&[1, 2, 1, 2]), vec![1, 2]);
        assert_eq!(minimal_period(&[7, 7, 7]), vec![7]);
        assert_eq!(minimal_period(&[1, 2, 3]), vec![1, 2, 3]);
    }
}
