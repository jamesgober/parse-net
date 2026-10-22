//! `Content-Disposition` (RFC 6266, and its use in `multipart/form-data`
//! part headers, RFC 7578 section 4.2).
//!
//! # Examples
//!
//! ```
//! use parse_net as pn;
//!
//! let cd = pn::parse_content_disposition(
//!     b"attachment; filename=\"EURO rates.txt\"; filename*=utf-8''%e2%82%ac%20rates.txt")?;
//! assert_eq!(cd.kind(), pn::DispositionType::Attachment);
//! let mut buf = [0u8; 64];
//! assert_eq!(cd.filename().expect("present").decode_into(&mut buf)?, "\u{20ac} rates.txt");
//! # Ok::<(), pn::ParseError>(())
//! ```

use crate::{
    class,
    error::{ErrorKind, ParseError, Result, WriteError, err},
    ext_value::{Charset, ExtValue, decode_checked, write_ext_value},
    limits::{DuplicatePolicy, Limits},
    param::{self, Params},
    scan::control_kind,
    text::{Word, skip_ows, trim_ows},
    write::{CountSink, Sink, reserve},
};

/// The disposition type.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DispositionType<'a> {
    /// `inline`.
    Inline,
    /// `attachment`.
    Attachment,
    /// `form-data` (RFC 7578).
    FormData,
    /// Another type token, as sent. RFC 6266 section 4.2: treat an unknown
    /// type as `attachment`.
    Other(&'a [u8]),
}

/// A validated `Content-Disposition` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContentDisposition<'a> {
    kind: DispositionType<'a>,
    params: Params<'a>,
}

/// Parses `Content-Disposition` with the default [`Limits`].
///
/// # Errors
///
/// As [`disposition::parse`](crate::disposition::parse).
///
/// # Examples
///
/// ```
/// let part = parse_net::parse_content_disposition(b"form-data; name=\"avatar\"; filename=\"../me.png\"")?;
/// assert!(part.name().is_some_and(|n| n.eq_bytes(b"avatar")));
/// assert!(part.filename().is_some_and(|f| f.has_path_separator()));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_content_disposition(value: &[u8]) -> Result<ContentDisposition<'_>> {
    parse(value, &Limits::DEFAULT)
}

/// Parses `disposition-type *( OWS ";" OWS disposition-parm )`.
///
/// The type token is case-insensitive. Repeated parameter names are refused
/// whatever `limits` says (a repeated `filename` is a known differential). A
/// `filename*` value must be an RFC 8187 value that decodes (valid UTF-8, no
/// control character); an invalid one refuses the whole field instead of
/// falling back to `filename` silently.
///
/// # Errors
///
/// [`ErrorKind::NotToken`] for the type; the parameter errors, with
/// [`ErrorKind::DuplicateParameter`]; the [`ExtValue::parse`] errors for
/// `filename*`; [`ErrorKind::TrailingData`].
///
/// # Examples
///
/// ```
/// use parse_net::{disposition, ErrorKind, Limits};
///
/// let dup = disposition::parse(b"attachment; filename=a.txt; filename=a.exe", &Limits::DEFAULT);
/// assert_eq!(dup.unwrap_err().kind(), ErrorKind::DuplicateParameter);
/// let bad = disposition::parse(b"attachment; filename=a.txt; filename*=UTF-8''%ZZ", &Limits::DEFAULT);
/// assert_eq!(bad.unwrap_err().kind(), ErrorKind::InvalidPercentEncoding);
/// ```
pub fn parse<'a>(value: &'a [u8], limits: &Limits) -> Result<ContentDisposition<'a>> {
    let lead = skip_ows(value);
    let v = trim_ows(value);
    let type_len = v.iter().take_while(|&&b| class::is_tchar(b)).count();
    if type_len == 0 {
        return Err(match v.first() {
            Some(&b) if b < 0x20 || b == 0x7f => ParseError::new(control_kind(b), lead),
            _ => ParseError::new(ErrorKind::NotToken, lead),
        });
    }
    let type_ = v.get(..type_len).unwrap_or(&[]);
    let refuse = limits.duplicate_params(DuplicatePolicy::Refuse);
    let rest = v.get(type_len..).unwrap_or(&[]);
    let (params, used) = param::parse(rest, &refuse).map_err(|e| e.shifted(lead + type_len))?;
    let end = type_len + used;
    if end < v.len() {
        let at = end + skip_ows(v.get(end..).unwrap_or(&[]));
        return Err(match v.get(at) {
            Some(&b) if b < 0x20 || b == 0x7f => ParseError::new(control_kind(b), lead + at),
            _ => ParseError::new(ErrorKind::TrailingData, lead + at),
        });
    }
    for p in params.iter() {
        if p.name.eq_ignore_ascii_case(b"filename*") {
            let at = lead
                + (p.name.as_ptr() as usize).saturating_sub(v.as_ptr() as usize)
                + p.name.len()
                + 1;
            let Word::Token(t) = p.value else {
                return err(ErrorKind::InvalidCharset, at);
            };
            let ext = ExtValue::parse(t).map_err(|e| e.shifted(at))?;
            // An undecodable `filename*` refuses the field, so no component
            // falls back to `filename` where another would not (T7).
            ext.check_text()
                .map_err(|e| ParseError::new(e.kind(), at))?;
        }
    }
    let kind = if type_.eq_ignore_ascii_case(b"inline") {
        DispositionType::Inline
    } else if type_.eq_ignore_ascii_case(b"attachment") {
        DispositionType::Attachment
    } else if type_.eq_ignore_ascii_case(b"form-data") {
        DispositionType::FormData
    } else {
        DispositionType::Other(type_)
    };
    Ok(ContentDisposition { kind, params })
}

impl<'a> ContentDisposition<'a> {
    /// The disposition type.
    #[must_use]
    pub const fn kind(&self) -> DispositionType<'a> {
        self.kind
    }

    /// Every parameter.
    #[must_use]
    pub const fn params(&self) -> Params<'a> {
        self.params
    }

    /// The `name` parameter (the field name of a `form-data` part).
    #[must_use]
    pub fn name(&self) -> Option<Word<'a>> {
        self.params.get("name")
    }

    /// The file name: `filename*` when present, else `filename` (RFC 6266
    /// section 4.3).
    #[must_use]
    pub fn filename(&self) -> Option<Filename<'a>> {
        self.filename_ext()
            .map(Filename::Ext)
            .or_else(|| self.filename_plain().map(Filename::Plain))
    }

    /// The `filename` parameter as sent.
    #[must_use]
    pub fn filename_plain(&self) -> Option<Word<'a>> {
        self.params.get("filename")
    }

    /// The `filename*` parameter, decoded as an RFC 8187 value.
    #[must_use]
    pub fn filename_ext(&self) -> Option<ExtValue<'a>> {
        match self.params.get("filename*")? {
            Word::Token(t) => ExtValue::parse(t).ok(),
            Word::Quoted(_) => None,
        }
    }
}

/// A file name from `Content-Disposition` or a `Link` `title`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Filename<'a> {
    /// The `filename` (or `title`) parameter.
    Plain(Word<'a>),
    /// The `filename*` (or `title*`) parameter.
    Ext(ExtValue<'a>),
}

/// The bytes of a word with quoted pairs replaced.
#[derive(Clone)]
enum WordBytes<'a> {
    Token(core::slice::Iter<'a, u8>),
    Quoted(crate::text::Unescape<'a>),
}

impl Iterator for WordBytes<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        match self {
            WordBytes::Token(t) => t.next().copied(),
            WordBytes::Quoted(q) => q.next(),
        }
    }
}

fn word_bytes<'a>(w: &Word<'a>) -> WordBytes<'a> {
    match w {
        Word::Token(t) => WordBytes::Token(t.iter()),
        Word::Quoted(q) => WordBytes::Quoted(q.bytes()),
    }
}

/// Percent-decoding over a byte iterator; a `%` without two hex digits is
/// kept as it is (the validating pass refuses it first).
#[derive(Clone)]
struct PctDecode<I> {
    inner: I,
}

impl<I: Iterator<Item = u8> + Clone> Iterator for PctDecode<I> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        let b = self.inner.next()?;
        if b != b'%' {
            return Some(b);
        }
        let mut look = self.inner.clone();
        match (
            look.next().and_then(class::hex_value),
            look.next().and_then(class::hex_value),
        ) {
            (Some(h), Some(l)) => {
                self.inner = look;
                Some((h << 4) | l)
            }
            _ => Some(b),
        }
    }
}

/// The index of the first `%` in `bytes` not followed by two hex digits.
fn has_bad_percent(bytes: impl Iterator<Item = u8>) -> Option<usize> {
    let mut pending: Option<usize> = None;
    for (i, b) in bytes.enumerate() {
        match pending {
            Some(at) if !class::is_hexdig(b) => return Some(at),
            Some(at) if i == at + 2 => pending = None,
            Some(_) => {}
            None if b == b'%' => pending = Some(i),
            None => {}
        }
    }
    pending
}

impl Filename<'_> {
    /// An upper bound on the length the `decode` functions write.
    #[must_use]
    pub fn max_decoded_len(&self) -> usize {
        match self {
            Filename::Plain(w) => w.len(),
            Filename::Ext(e) => e.max_decoded_len(),
        }
    }

    /// Decodes into `out`: the unescaped `filename` as UTF-8, or the decoded
    /// `filename*`. Separators (`/`, `\`) pass through; see
    /// [`has_path_separator`](Self::has_path_separator).
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidUtf8`], [`ErrorKind::ControlInDecoded`],
    /// [`ErrorKind::BufferTooSmall`]. Nothing is written on error.
    pub fn decode_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str> {
        match self {
            Filename::Plain(w) => decode_checked(word_bytes(w), Charset::Utf8, out),
            Filename::Ext(e) => e.decode_into(out),
        }
    }

    /// As [`decode_into`](Self::decode_into), and `%XX` in a plain
    /// `filename` is decoded too (RFC 7578 section 2 percent-encoded file
    /// names).
    ///
    /// # Errors
    ///
    /// As [`decode_into`](Self::decode_into), and
    /// [`ErrorKind::InvalidPercentEncoding`].
    ///
    /// # Examples
    ///
    /// ```
    /// let cd = parse_net::parse_content_disposition(b"form-data; name=f; filename=\"caf%C3%A9.txt\"")?;
    /// let mut buf = [0u8; 32];
    /// assert_eq!(cd.filename().expect("present").decode_percent_into(&mut buf)?, "caf\u{e9}.txt");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn decode_percent_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str> {
        match self {
            Filename::Plain(w) => {
                if let Some(at) = has_bad_percent(word_bytes(w)) {
                    return err(ErrorKind::InvalidPercentEncoding, at);
                }
                decode_checked(
                    PctDecode {
                        inner: word_bytes(w),
                    },
                    Charset::Utf8,
                    out,
                )
            }
            Filename::Ext(e) => e.decode_into(out),
        }
    }

    /// Whether the decoded name contains `/` or `\` (in a plain name, also
    /// after percent-decoding). The file-name policy belongs to the caller
    /// (path-lib, customs-sec).
    #[must_use]
    pub fn has_path_separator(&self) -> bool {
        let sep = |b: u8| b == b'/' || b == b'\\';
        match self {
            Filename::Plain(w) => {
                word_bytes(w).any(sep)
                    || PctDecode {
                        inner: word_bytes(w),
                    }
                    .any(sep)
            }
            Filename::Ext(e) => e.raw_bytes().any(sep),
        }
    }

    /// Whether the decoded name contains a bidirectional control character
    /// (U+202A to U+202E, U+2066 to U+2069), used to disguise an extension
    /// (`exe.txt` shown for `txt.exe`). Reported, not refused.
    ///
    /// # Examples
    ///
    /// ```
    /// let cd = parse_net::parse_content_disposition(b"attachment; filename*=UTF-8''invoice%E2%80%AEfdp.exe")?;
    /// assert!(cd.filename().expect("present").has_bidi_control());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn has_bidi_control(&self) -> bool {
        fn scan(bytes: impl Iterator<Item = u8>) -> bool {
            let (mut a, mut b) = (0u8, 0u8);
            for c in bytes {
                if a == 0xe2
                    && ((b == 0x80 && (0xaa..=0xae).contains(&c))
                        || (b == 0x81 && (0xa6..=0xa9).contains(&c)))
                {
                    return true;
                }
                a = b;
                b = c;
            }
            false
        }
        match self {
            Filename::Plain(w) => {
                scan(word_bytes(w))
                    || scan(PctDecode {
                        inner: word_bytes(w),
                    })
            }
            Filename::Ext(e) if e.charset() == Charset::Utf8 => scan(e.raw_bytes()),
            Filename::Ext(_) => false,
        }
    }
}

/// Whether `c` must not appear in the ASCII fallback name.
fn needs_fallback(c: char) -> bool {
    !c.is_ascii() || c == '"' || c == '\\' || c.is_ascii_control()
}

fn put_attachment(filename: &str, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
    out.put(b"attachment; filename=\"")?;
    for c in filename.chars() {
        if needs_fallback(c) {
            out.put(b"_")?;
        } else {
            let mut buf = [0u8; 4];
            out.put(c.encode_utf8(&mut buf).as_bytes())?;
        }
    }
    out.put(b"\"")?;
    if filename.chars().any(needs_fallback) {
        out.put(b"; filename*=")?;
        write_ext_value(filename, out)?;
    }
    Ok(())
}

/// Writes `attachment; filename="<ASCII fallback>"`, followed by
/// `; filename*=UTF-8''<encoded>` when the name is not plain printable ASCII
/// without `"` and `\`. The fallback replaces each such character with `_`.
///
/// # Errors
///
/// [`WriteError::Forbidden`] for a control character in `filename`;
/// [`WriteError::Full`] (nothing written when the sink reports its room).
///
/// # Examples
///
/// ```
/// use parse_net::{write_attachment, SliceSink};
///
/// let mut buf = [0u8; 96];
/// let mut out = SliceSink::new(&mut buf);
/// write_attachment("\u{20ac} rates.txt", &mut out).expect("room");
/// assert_eq!(out.written(), b"attachment; filename=\"_ rates.txt\"; filename*=UTF-8''%E2%82%AC%20rates.txt");
/// ```
pub fn write_attachment(
    filename: &str,
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    for (i, c) in filename.char_indices() {
        let p = u32::from(c);
        if p < 0x20 || (0x7f..=0x9f).contains(&p) {
            return Err(WriteError::forbidden(i));
        }
    }
    let mut count = CountSink::new();
    put_attachment(filename, &mut count)?;
    reserve(out, count.count())?;
    put_attachment(filename, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cd(v: &[u8]) -> Result<ContentDisposition<'_>> {
        parse_content_disposition(v)
    }

    fn name(v: &[u8]) -> std::string::String {
        let mut buf = [0u8; 128];
        cd(v)
            .unwrap()
            .filename()
            .unwrap()
            .decode_into(&mut buf)
            .unwrap()
            .into()
    }

    #[test]
    fn test_disposition_types_and_params() {
        assert_eq!(cd(b"inline").unwrap().kind(), DispositionType::Inline);
        assert_eq!(
            cd(b"ATTACHMENT;").unwrap().kind(),
            DispositionType::Attachment
        );
        assert_eq!(
            cd(b"form-data; name=\"a\"; filename=\"\"").unwrap().kind(),
            DispositionType::FormData
        );
        assert_eq!(
            cd(b"x-custom").unwrap().kind(),
            DispositionType::Other(b"x-custom")
        );
        assert_eq!(cd(b"").unwrap_err().kind(), ErrorKind::NotToken);
        assert_eq!(
            cd(b"attachment x").unwrap_err().kind(),
            ErrorKind::TrailingData
        );
        assert_eq!(
            cd(b"attachment; filename=a\rb").unwrap_err().kind(),
            ErrorKind::BareCr
        );
        assert!(cd(b"attachment").unwrap().filename().is_none());
    }

    #[test]
    fn test_filename_precedence_and_refusals() {
        assert_eq!(
            name(b"attachment; filename=\"a.txt\"; filename*=UTF-8''b.txt"),
            "b.txt"
        );
        assert_eq!(
            name(b"attachment; filename*=UTF-8''b.txt; filename=\"a.txt\""),
            "b.txt"
        );
        assert_eq!(
            name(b"attachment; filename=\"a \\\"q\\\".txt\""),
            "a \"q\".txt"
        );
        let k = |v: &[u8]| cd(v).unwrap_err().kind();
        // T7: an invalid filename* refuses the field.
        assert_eq!(
            k(b"attachment; filename=\"a.txt\"; filename*=UTF-8''%C3"),
            ErrorKind::InvalidUtf8
        );
        assert_eq!(
            k(b"attachment; filename*=\"UTF-8''a\""),
            ErrorKind::InvalidCharset
        );
        assert_eq!(
            k(b"attachment; filename*=UTF-16''a"),
            ErrorKind::UnsupportedCharset
        );
        // T4: duplicates refused, whatever the limits say.
        let last = Limits::DEFAULT.duplicate_params(DuplicatePolicy::Last);
        assert_eq!(
            parse(b"attachment; filename=a; FILENAME=b", &last)
                .unwrap_err()
                .kind(),
            ErrorKind::DuplicateParameter
        );
    }

    #[test]
    fn test_filename_nul_refused() {
        let mut buf = [0u8; 32];
        let e = cd(b"attachment; filename*=UTF-8''a%00.txt").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::ControlInDecoded, 22));
        let p = cd(b"form-data; name=x; filename=\"a%00b\"").unwrap();
        assert_eq!(
            p.filename()
                .unwrap()
                .decode_percent_into(&mut buf)
                .unwrap_err()
                .kind(),
            ErrorKind::ControlInDecoded
        );
        assert_eq!(
            p.filename().unwrap().decode_into(&mut buf).unwrap(),
            "a%00b"
        );
    }

    #[test]
    fn test_filename_overlong_utf8_refused() {
        let mut buf = [0u8; 32];
        assert_eq!(
            cd(b"attachment; filename*=UTF-8''%C0%AF")
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidUtf8
        );
        let p = cd(b"attachment; filename=\"\xc0\xaf\"").unwrap();
        assert_eq!(
            p.filename()
                .unwrap()
                .decode_into(&mut buf)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidUtf8
        );
    }

    #[test]
    fn test_filename_separators_and_bidi_reported() {
        fn f(v: &[u8]) -> Filename<'_> {
            cd(v).unwrap().filename().unwrap()
        }
        assert!(f(b"attachment; filename=\"../x\"").has_path_separator());
        assert!(f(b"attachment; filename=\"a\\\\b\"").has_path_separator());
        assert!(f(b"attachment; filename=\"a%2Fb\"").has_path_separator());
        assert!(f(b"attachment; filename*=UTF-8''a%2Fb").has_path_separator());
        assert!(!f(b"attachment; filename=plain.txt").has_path_separator());
        assert!(f(b"attachment; filename*=UTF-8''%E2%81%A6x").has_bidi_control());
        assert!(!f(b"attachment; filename*=UTF-8''%E2%82%AC").has_bidi_control());
        assert!(!f(b"attachment; filename*=ISO-8859-1''%E2%A1%AE").has_bidi_control());
        assert_eq!(
            cd(b"attachment; filename*=ISO-8859-1''%85")
                .unwrap_err()
                .kind(),
            ErrorKind::ControlInDecoded
        );
    }

    #[test]
    fn test_decode_percent_into_errors() {
        let mut buf = [0u8; 32];
        let p = cd(b"form-data; name=x; filename=\"a%zz\"").unwrap();
        assert_eq!(
            p.filename()
                .unwrap()
                .decode_percent_into(&mut buf)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidPercentEncoding
        );
        let p = cd(b"form-data; name=x; filename=\"a%4\"").unwrap();
        assert_eq!(
            p.filename()
                .unwrap()
                .decode_percent_into(&mut buf)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidPercentEncoding
        );
    }

    #[test]
    fn test_write_attachment_cases() {
        let mut buf = [0u8; 128];
        let mut out = crate::SliceSink::new(&mut buf);
        write_attachment("report.pdf", &mut out).unwrap();
        assert_eq!(out.written(), b"attachment; filename=\"report.pdf\"");
        let back = cd(out.written()).unwrap();
        assert!(back.filename_ext().is_none());
        out.clear();
        write_attachment("a\"b\\c", &mut out).unwrap();
        assert_eq!(
            out.written(),
            b"attachment; filename=\"a_b_c\"; filename*=UTF-8''a%22b%5Cc"
        );
        let mut dec = [0u8; 16];
        assert_eq!(
            cd(out.written())
                .unwrap()
                .filename()
                .unwrap()
                .decode_into(&mut dec)
                .unwrap(),
            "a\"b\\c"
        );
        assert_eq!(
            write_attachment("a\nb", &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        let mut small = [0u8; 10];
        let mut out = crate::SliceSink::new(&mut small);
        assert_eq!(write_attachment("x", &mut out), Err(WriteError::Full));
        assert!(out.is_empty());
    }
}
