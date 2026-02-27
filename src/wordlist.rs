//! BIP39 English wordlist (2048 words) — compact storage.
//!
//! Words are stored as a single embedded string (include_str!) instead of
//! 2048 separate `&str` pointers. This saves ~16KB on 32-bit targets by
//! eliminating the pointer+length metadata array.
//!
//! Source: <https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt>

/// The raw wordlist as a single newline-delimited string.
const RAW: &str = include_str!("english.txt");

/// Get the word at `index` (0..2047) by scanning the embedded string.
///
/// Returns `None` if index >= 2048.
pub fn get_word(index: usize) -> Option<&'static str> {
    if index >= 2048 {
        return None;
    }
    let mut pos = 0;
    let bytes = RAW.as_bytes();
    for _ in 0..index {
        while pos < bytes.len() && bytes[pos] != b'\n' {
            pos += 1;
        }
        pos += 1; // skip newline
    }
    let start = pos;
    while pos < bytes.len() && bytes[pos] != b'\n' {
        pos += 1;
    }
    Some(&RAW[start..pos])
}

/// Find the index (0..2047) of a word. Returns `None` if not found.
pub fn find_word(word: &str) -> Option<usize> {
    let mut idx = 0;
    let mut pos = 0;
    let bytes = RAW.as_bytes();
    let word_bytes = word.as_bytes();
    while pos < bytes.len() {
        let start = pos;
        while pos < bytes.len() && bytes[pos] != b'\n' {
            pos += 1;
        }
        let end = pos;
        if end - start == word_bytes.len() && &bytes[start..end] == word_bytes {
            return Some(idx);
        }
        pos += 1; // skip newline
        idx += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_word() {
        assert_eq!(get_word(0), Some("abandon"));
    }

    #[test]
    fn last_word() {
        assert_eq!(get_word(2047), Some("zoo"));
    }

    #[test]
    fn out_of_bounds() {
        assert_eq!(get_word(2048), None);
    }

    #[test]
    fn find_abandon() {
        assert_eq!(find_word("abandon"), Some(0));
    }

    #[test]
    fn find_zoo() {
        assert_eq!(find_word("zoo"), Some(2047));
    }

    #[test]
    fn find_unknown() {
        assert_eq!(find_word("notaword"), None);
    }

    #[test]
    fn roundtrip_all_words() {
        for i in 0..2048 {
            let word = get_word(i).unwrap();
            assert_eq!(find_word(word), Some(i), "roundtrip failed for index {}", i);
        }
    }
}
