//! Base64 for RFC 2047 `B` encoded words only (D-080): one word at a time,
//! into a buffer on the stack. Not a public codec.

/// The base64 alphabet (RFC 2045 section 6.8).
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The six-bit value of every byte, or 0xff for a byte outside the alphabet.
// Built at compile time; `i` runs over 0..64, the alphabet's own bounds.
#[allow(clippy::indexing_slicing)]
const VALUE: [u8; 256] = {
    let mut t = [0xffu8; 256];
    let mut i = 0usize;
    while i < 64 {
        t[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    t
};

/// The encoded length of `n` bytes, padding included.
pub(super) const fn encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Encodes `input` into `out`, which has room for [`encoded_len`] of it;
/// returns the length written.
pub(super) fn encode(input: &[u8], out: &mut [u8]) -> usize {
    let sym = |v: u32| ALPHABET.get((v & 63) as usize).copied().unwrap_or(b'A');
    let mut n = 0usize;
    for chunk in input.chunks(3) {
        let a = u32::from(chunk.first().copied().unwrap_or(0));
        let b = u32::from(chunk.get(1).copied().unwrap_or(0));
        let c = u32::from(chunk.get(2).copied().unwrap_or(0));
        let v = (a << 16) | (b << 8) | c;
        let quad = [
            sym(v >> 18),
            sym(v >> 12),
            if chunk.len() > 1 { sym(v >> 6) } else { b'=' },
            if chunk.len() > 2 { sym(v) } else { b'=' },
        ];
        if let Some(d) = out.get_mut(n..n + 4) {
            d.copy_from_slice(&quad);
        }
        n += 4;
    }
    n
}

/// The most bytes one encoded word decodes to: a word is at most 75 bytes,
/// at least 8 of them `=?`, a charset, `?B?`, and `?=`, so its text is at
/// most 64 base64 characters.
pub(super) const MAX_DECODED: usize = 48;

/// Decodes the text of one `B` word, strictly: whole groups of four, `=`
/// only as the last one or two characters, and zero bits under the padding,
/// so every byte string has one encoding. `Err` holds the index of the first
/// character refused.
pub(super) fn decode(
    text: &[u8],
    out: &mut [u8; MAX_DECODED],
) -> core::result::Result<usize, usize> {
    if text.len() % 4 != 0 {
        return Err(text.len() - text.len() % 4);
    }
    if text.len() / 4 * 3 > MAX_DECODED {
        return Err(MAX_DECODED / 3 * 4);
    }
    let six = |b: u8| VALUE.get(usize::from(b)).copied().unwrap_or(0xff);
    // The first character of `quad` outside the alphabet, at its index.
    let bad = |at: usize, quad: &[u8]| at + quad.iter().position(|&b| six(b) == 0xff).unwrap_or(0);
    let (body, last) = text.split_at(text.len().saturating_sub(4));
    let mut n = 0usize;
    // Every group but the last: four characters of the alphabet, three
    // bytes. 0xff, the mark of a byte outside it, survives the OR.
    for (q, quad) in body.chunks_exact(4).enumerate() {
        let &[a, b, c, d] = quad else { continue };
        let (a, b, c, d) = (six(a), six(b), six(c), six(d));
        if (a | b | c | d) & 0x80 != 0 {
            return Err(bad(q * 4, quad));
        }
        let v = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
        if let Some(dst) = out.get_mut(n..n + 3) {
            dst.copy_from_slice(&[(v >> 16) as u8, (v >> 8) as u8, v as u8]);
        }
        n += 3;
    }
    // The last group may end in one or two `=`, with zero bits under them
    // (RFC 4648 section 3.5).
    let &[a, b, c, d] = last else {
        return Ok(n);
    };
    let at = body.len();
    let pad = match (c, d) {
        (b'=', b'=') => 2,
        (_, b'=') => 1,
        _ => 0,
    };
    let kept = last.get(..4 - pad).unwrap_or(&[]);
    if kept.iter().any(|&x| six(x) == 0xff) {
        return Err(bad(at, kept));
    }
    let (a, b) = (six(a), six(b));
    let (c, d) = (
        if pad == 2 { 0 } else { six(c) },
        if pad >= 1 { 0 } else { six(d) },
    );
    if (pad == 2 && b & 0x0f != 0) || (pad == 1 && c & 0x03 != 0) {
        return Err(at + 3 - pad);
    }
    let v = (u32::from(a) << 18) | (u32::from(b) << 12) | (u32::from(c) << 6) | u32::from(d);
    let bytes = [(v >> 16) as u8, (v >> 8) as u8, v as u8];
    let keep = 3 - pad;
    if let (Some(dst), Some(src)) = (out.get_mut(n..n + keep), bytes.get(..keep)) {
        dst.copy_from_slice(src);
    }
    n += keep;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(s: &[u8]) -> core::result::Result<std::vec::Vec<u8>, usize> {
        let mut out = [0u8; MAX_DECODED];
        decode(s, &mut out).map(|n| out[..n].to_vec())
    }

    fn enc(s: &[u8]) -> std::vec::Vec<u8> {
        let mut out = [0u8; 128];
        let n = encode(s, &mut out);
        assert_eq!(n, encoded_len(s.len()));
        out[..n].to_vec()
    }

    #[test]
    fn test_rfc4648_vectors_both_ways() {
        // RFC 4648 section 10.
        for (plain, coded) in [
            (&b""[..], &b""[..]),
            (b"f", b"Zg=="),
            (b"fo", b"Zm8="),
            (b"foo", b"Zm9v"),
            (b"foob", b"Zm9vYg=="),
            (b"fooba", b"Zm9vYmE="),
            (b"foobar", b"Zm9vYmFy"),
        ] {
            assert_eq!(enc(plain), coded);
            assert_eq!(dec(coded).unwrap(), plain);
        }
        assert_eq!(enc(&[0xff, 0xfe]), b"//4=");
        assert_eq!(dec(b"+/+/").unwrap(), [0xfb, 0xff, 0xbf]);
    }

    #[test]
    fn test_decode_is_strict() {
        // Not whole groups of four.
        assert_eq!(dec(b"Zg="), Err(0));
        assert_eq!(dec(b"Zm9vY"), Err(4));
        // Outside the alphabet, whitespace and URL-safe letters included.
        assert_eq!(dec(b"Zm 9"), Err(2));
        assert_eq!(dec(b"Zm-9"), Err(2));
        assert_eq!(dec(b"Zm_9"), Err(2));
        assert_eq!(dec(b"Zm9\n"), Err(3));
        // `=` anywhere but the end, and three of them.
        assert_eq!(dec(b"Zg==Zm9v"), Err(2));
        assert_eq!(dec(b"Z===").unwrap_err(), 1);
        assert_eq!(dec(b"=g=="), Err(0));
        assert_eq!(dec(b"Zm=v"), Err(2));
        // Bits under the padding.
        assert_eq!(dec(b"Zh=="), Err(1));
        assert_eq!(dec(b"Zm9="), Err(2));
        assert_eq!(dec(b"Zm8=").unwrap(), b"fo");
        // At most one word's worth.
        assert_eq!(dec(&[b'A'; 64]).unwrap().len(), 48);
        assert_eq!(dec(&[b'A'; 68]), Err(64));
    }

    proptest::proptest! {
        #[test]
        fn test_round_trip(v in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=48)) {
            proptest::prop_assert_eq!(dec(&enc(&v)).unwrap(), v);
        }

        #[test]
        fn test_decode_accepts_only_canonical_text(s in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..=64)) {
            // Whatever decodes encodes back to exactly the same text.
            if let Ok(bytes) = dec(&s) {
                proptest::prop_assert_eq!(enc(&bytes), s);
            }
        }
    }
}
