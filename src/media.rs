//! Media types: `type "/" subtype parameters` (RFC 9110 section 8.3.1), and
//! the RFC 2046 multipart boundary.
//!
//! Type, subtype, and parameter names are case-insensitive; parameter values
//! are case-sensitive unless the parameter's definition says otherwise
//! (`charset` is case-insensitive, RFC 9110 section 8.3.2).
//!
//! # Examples
//!
//! ```
//! use parse_net as pn;
//!
//! let mt = pn::parse_media_type(b"Multipart/Form-Data; boundary=\"----x y\"")?;
//! assert!(mt.is_multipart_form_data() && mt.is("multipart", "form-data"));
//! assert_eq!(mt.boundary()?.map(|b| b.as_bytes()), Some(&b"----x y"[..]));
//!
//! assert_eq!(pn::parse_media_type(b"text/*").unwrap_err().kind(), pn::ErrorKind::Wildcard);
//!
//! let mut buf = [0u8; 64];
//! let mut out = pn::SliceSink::new(&mut buf);
//! pn::media::write("text", "plain", &[("charset", "utf-8")], &mut out)?;
//! assert_eq!(out.written(), b"text/plain; charset=utf-8");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::{
    class,
    error::{ErrorKind, ParseError, Result, WriteError, err},
    limits::Limits,
    negotiate::QValue,
    param::{self, Params},
    scan::control_kind,
    text::{Word, is_token, skip_ows, trim_ows},
    write::{Sink, reserve, unique_names, word_len, write_word},
};

/// Parses a `Content-Type` style media type with the default [`Limits`].
///
/// # Errors
///
/// As [`parse`].
///
/// # Examples
///
/// ```
/// let mt = parse_net::parse_media_type(b"text/html; charset=UTF-8")?;
/// assert!(mt.essence_is("text/html"));
/// assert!(mt.charset().is_some_and(|c| c.eq_ignore_ascii_case(b"utf-8")));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_media_type(value: &[u8]) -> Result<MediaType<'_>> {
    parse(value, &Limits::DEFAULT)
}

/// The error for a byte that ends a media type where it may not.
fn bad_byte(value: &[u8], at: usize) -> ParseError {
    match value.get(at) {
        Some(&b) if crate::scan::is_control(b) => ParseError::new(control_kind(b), at),
        _ => ParseError::new(ErrorKind::InvalidMediaType, at),
    }
}

/// Parses `type "/" subtype` at the start of `value` (OWS already skipped);
/// returns both and the bytes used.
fn essence(value: &[u8], base: usize) -> Result<(&[u8], &[u8], usize)> {
    let type_len = value.iter().take_while(|&&b| class::is_tchar(b)).count();
    if type_len == 0 {
        return Err(bad_byte(value, 0).shifted(base));
    }
    if value.get(type_len) != Some(&b'/') {
        return Err(bad_byte(value, type_len).shifted(base));
    }
    let sub_start = type_len + 1;
    let sub_len = value
        .get(sub_start..)
        .unwrap_or(&[])
        .iter()
        .take_while(|&&b| class::is_tchar(b))
        .count();
    if sub_len == 0 {
        return Err(bad_byte(value, sub_start).shifted(base));
    }
    let type_ = value.get(..type_len).unwrap_or(&[]);
    let subtype = value.get(sub_start..sub_start + sub_len).unwrap_or(&[]);
    Ok((type_, subtype, sub_start + sub_len))
}

/// Parses a media type, as in `Content-Type`.
///
/// Type and subtype are tokens around `/`; OWS is allowed only before `;` and
/// around the whole value; parameters follow the RFC 9110 grammar with the
/// duplicate policy of `limits` (refusal by default, so `charset` or
/// `boundary` given twice is refused).
///
/// # Errors
///
/// [`ErrorKind::InvalidMediaType`] for a missing `/`, an empty or non-token
/// type or subtype, whitespace inside the essence, or bytes after the
/// parameters; [`ErrorKind::Wildcard`] for `*` as type or subtype; a control
/// kind for a control byte; the parameter errors of
/// [`param::parse`].
///
/// # Examples
///
/// ```
/// use parse_net::{media, ErrorKind, Limits};
///
/// let err = media::parse(b"text/ html", &Limits::DEFAULT).unwrap_err();
/// assert_eq!((err.kind(), err.offset()), (ErrorKind::InvalidMediaType, 5));
/// assert_eq!(err.to_string(), "invalid media type at offset 5");
/// ```
pub fn parse<'a>(value: &'a [u8], limits: &Limits) -> Result<MediaType<'a>> {
    let lead = skip_ows(value);
    let trimmed = trim_ows(value);
    let (type_, subtype, used) = essence(trimmed, lead)?;
    if type_ == b"*" {
        return err(ErrorKind::Wildcard, lead);
    }
    if subtype == b"*" {
        return err(ErrorKind::Wildcard, lead + type_.len() + 1);
    }
    let rest = trimmed.get(used..).unwrap_or(&[]);
    let (params, n) = param::parse(rest, limits).map_err(|e| e.shifted(lead + used))?;
    let end = used + n;
    if end < trimmed.len() {
        let at = end + skip_ows(trimmed.get(end..).unwrap_or(&[]));
        return Err(bad_byte(trimmed, at).shifted(lead));
    }
    Ok(MediaType {
        type_,
        subtype,
        params,
    })
}

/// Parses a media range, as in one member of `Accept`: `*/*`, `type/*`, or a
/// media type, with an optional weight.
///
/// The first parameter named `q` (ASCII case-insensitive) is the weight; it
/// and every parameter after it are `accept-ext` and take no part in
/// matching (RFC 9110 section 12.5.1). A range without `q` has weight 1.
///
/// # Errors
///
/// [`ErrorKind::Wildcard`] for `*/subtype`; [`ErrorKind::InvalidQValue`];
/// the errors of [`parse`].
///
/// # Examples
///
/// ```
/// use parse_net::{media, Limits};
///
/// let r = media::parse_range(b"text/*;q=0.5", &Limits::DEFAULT)?;
/// assert_eq!((r.specificity(), r.weight().thousandths()), (2, 500));
/// let html = parse_net::parse_media_type(b"text/html")?;
/// assert!(r.matches(&html));
/// assert!(media::parse_range(b"*/html", &Limits::DEFAULT).is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_range<'a>(value: &'a [u8], limits: &Limits) -> Result<MediaRange<'a>> {
    let lead = skip_ows(value);
    let trimmed = trim_ows(value);
    let (type_, subtype, used) = essence(trimmed, lead)?;
    if type_ == b"*" && subtype != b"*" {
        return err(ErrorKind::Wildcard, lead + type_.len() + 1);
    }
    let rest = trimmed.get(used..).unwrap_or(&[]);
    let (all, n) = param::parse(rest, limits).map_err(|e| e.shifted(lead + used))?;
    let end = used + n;
    if end < trimmed.len() {
        let at = end + skip_ows(trimmed.get(end..).unwrap_or(&[]));
        return Err(bad_byte(trimmed, at).shifted(lead));
    }
    let (params, q) = all.split_at_name(b"q");
    let weight = match q {
        None => QValue::ONE,
        Some(p) => match p.value {
            Word::Token(t) => QValue::parse(t).map_err(|e| {
                let at = (t.as_ptr() as usize).saturating_sub(value.as_ptr() as usize);
                ParseError::new(e.kind(), at)
            })?,
            Word::Quoted(_) => {
                let at = (p.name.as_ptr() as usize).saturating_sub(value.as_ptr() as usize);
                return err(ErrorKind::InvalidQValue, at);
            }
        },
    };
    Ok(MediaRange {
        type_,
        subtype,
        params,
        weight,
    })
}

/// A validated media range from `Accept`.
///
/// # Examples
///
/// ```
/// use parse_net::{media, Limits};
///
/// let r = media::parse_range(b"text/html;level=1;q=0.7;ext=x", &Limits::DEFAULT)?;
/// assert_eq!(r.params().len(), 1);              // `level` only: `q` ends the media-type parameters
/// assert_eq!(r.weight().thousandths(), 700);
/// assert_eq!(r.specificity(), 4);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MediaRange<'a> {
    type_: &'a [u8],
    subtype: &'a [u8],
    params: Params<'a>,
    weight: QValue,
}

impl<'a> MediaRange<'a> {
    /// The type, or `*`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{media, Limits};
    ///
    /// let r = media::parse_range(b"text/*", &Limits::DEFAULT)?;
    /// assert_eq!(r.type_(), b"text");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn type_(&self) -> &'a [u8] {
        self.type_
    }

    /// The subtype, or `*`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{media, Limits};
    ///
    /// assert_eq!(media::parse_range(b"text/*", &Limits::DEFAULT)?.subtype(), b"*");
    /// assert_eq!(media::parse_range(b"text/csv", &Limits::DEFAULT)?.subtype(), b"csv");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn subtype(&self) -> &'a [u8] {
        self.subtype
    }

    /// Whether this range matches `offer`: the type and subtype match (or
    /// are `*`), and every parameter of the range is present in the offer
    /// with an equal value (case-sensitive, except `charset`).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{media, parse_media_type, Limits};
    ///
    /// let r = media::parse_range(b"text/html;charset=utf-8", &Limits::DEFAULT)?;
    /// assert!(r.matches(&parse_media_type(b"text/html; charset=UTF-8")?));
    /// assert!(!r.matches(&parse_media_type(b"text/html")?));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn matches(&self, offer: &MediaType<'_>) -> bool {
        let type_ok = self.type_ == b"*" || self.type_.eq_ignore_ascii_case(offer.type_());
        let sub_ok = self.subtype == b"*" || self.subtype.eq_ignore_ascii_case(offer.subtype());
        type_ok
            && sub_ok
            && self.params.iter().all(|p| {
                let charset = p.name.eq_ignore_ascii_case(b"charset");
                offer.params().iter().any(|o| {
                    o.name.eq_ignore_ascii_case(p.name) && p.value.same_value(&o.value, charset)
                })
            })
    }

    /// How specific the range is: 4 for a type with parameters, 3 for an
    /// exact type, 2 for `type/*`, 1 for `*/*`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{media, Limits};
    ///
    /// let s = |v: &[u8]| media::parse_range(v, &Limits::DEFAULT).map(|r| r.specificity());
    /// assert_eq!((s(b"*/*")?, s(b"image/*")?, s(b"image/png")?, s(b"image/png;x=1")?), (1, 2, 3, 4));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn specificity(&self) -> u8 {
        if matches!(self.type_, [b'*']) {
            1
        } else if matches!(self.subtype, [b'*']) {
            2
        } else if self.params.is_empty() {
            3
        } else {
            4
        }
    }

    /// The weight (`q`), 1 when absent.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{media, Limits, QValue};
    ///
    /// assert_eq!(media::parse_range(b"text/html;q=0.25", &Limits::DEFAULT)?.weight().thousandths(), 250);
    /// assert_eq!(media::parse_range(b"text/html", &Limits::DEFAULT)?.weight(), QValue::ONE);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn weight(&self) -> QValue {
        self.weight
    }

    /// The media-type parameters: those before `q`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{media, Limits};
    ///
    /// let r = media::parse_range(b"text/html;level=1;q=0.5", &Limits::DEFAULT)?;
    /// assert_eq!(r.params().get("level").and_then(|w| w.as_str()), Some("1"));
    /// assert!(r.params().get("q").is_none());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn params(&self) -> Params<'a> {
        self.params
    }
}

/// Writes `type/subtype` and then `; name=value` for each pair, values as a
/// token when they are one and as a quoted string otherwise.
///
/// # Errors
///
/// [`WriteError::NotToken`] for a type, subtype, or name that is not a token
/// (or is `*`); [`WriteError::DuplicateName`] for two parameters with the
/// same name (ASCII case-insensitive), which parsers refuse;
/// [`WriteError::Forbidden`] for a control byte in a value;
/// [`WriteError::Full`]. Nothing is written on error when the sink reports
/// its room.
///
/// # Examples
///
/// ```
/// use parse_net::{media, SliceSink};
///
/// let mut buf = [0u8; 64];
/// let mut out = SliceSink::new(&mut buf);
/// media::write("multipart", "form-data", &[("boundary", "a b")], &mut out)?;
/// assert_eq!(out.written(), b"multipart/form-data; boundary=\"a b\"");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
pub fn write(
    type_: &str,
    subtype: &str,
    params: &[(&str, &str)],
    out: &mut impl Sink,
) -> core::result::Result<(), WriteError> {
    let (t, s) = (type_.as_bytes(), subtype.as_bytes());
    if !is_token(t) || !is_token(s) || t == b"*" || s == b"*" {
        return Err(WriteError::NotToken);
    }
    unique_names(params)?;
    let mut len = t.len().saturating_add(1).saturating_add(s.len());
    for (name, value) in params {
        if !is_token(name.as_bytes()) {
            return Err(WriteError::NotToken);
        }
        let v = word_len(value.as_bytes())?;
        len = len
            .saturating_add(3)
            .saturating_add(name.len())
            .saturating_add(v);
    }
    reserve(out, len)?;
    out.put(t)?;
    out.put(b"/")?;
    out.put(s)?;
    for (name, value) in params {
        out.put(b"; ")?;
        out.put(name.as_bytes())?;
        out.put(b"=")?;
        write_word(value.as_bytes(), out)?;
    }
    Ok(())
}

/// A validated media type.
///
/// # Examples
///
/// ```
/// let ld = parse_net::parse_media_type(b"application/ld+json")?;
/// assert_eq!(ld.suffix(), Some(&b"json"[..]));
/// assert!(ld.is_json());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MediaType<'a> {
    pub(crate) type_: &'a [u8],
    pub(crate) subtype: &'a [u8],
    pub(crate) params: Params<'a>,
}

impl<'a> MediaType<'a> {
    /// The type, as sent.
    ///
    /// # Examples
    ///
    /// ```
    /// let mt = parse_net::parse_media_type(b"Text/HTML")?;
    /// assert_eq!(mt.type_(), b"Text");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn type_(&self) -> &'a [u8] {
        self.type_
    }

    /// The subtype, as sent.
    ///
    /// # Examples
    ///
    /// ```
    /// let mt = parse_net::parse_media_type(b"Text/HTML; charset=utf-8")?;
    /// assert_eq!(mt.subtype(), b"HTML");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn subtype(&self) -> &'a [u8] {
        self.subtype
    }

    /// The structured syntax suffix: the part of the subtype after its last
    /// `+` (`json` of `ld+json`), when there is one.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::parse_media_type;
    ///
    /// assert_eq!(parse_media_type(b"image/svg+xml")?.suffix(), Some(&b"xml"[..]));
    /// assert_eq!(parse_media_type(b"text/plain")?.suffix(), None);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn suffix(&self) -> Option<&'a [u8]> {
        let plus = self.subtype.iter().rposition(|&b| b == b'+')?;
        self.subtype.get(plus + 1..).filter(|s| !s.is_empty())
    }

    /// Whether `type/subtype` equals `essence`, ignoring ASCII case.
    ///
    /// # Examples
    ///
    /// ```
    /// let mt = parse_net::parse_media_type(b"Application/JSON; charset=utf-8")?;
    /// assert!(mt.essence_is("application/json"));
    /// assert!(!mt.essence_is("application"));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn essence_is(&self, essence: &str) -> bool {
        match essence.split_once('/') {
            Some((t, s)) => self.is(t, s),
            None => false,
        }
    }

    /// Whether the type and subtype equal `type_` and `subtype`, ignoring
    /// ASCII case.
    ///
    /// # Examples
    ///
    /// ```
    /// let mt = parse_net::parse_media_type(b"TEXT/html")?;
    /// assert!(mt.is("text", "HTML") && !mt.is("text", "plain"));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn is(&self, type_: &str, subtype: &str) -> bool {
        self.type_.eq_ignore_ascii_case(type_.as_bytes())
            && self.subtype.eq_ignore_ascii_case(subtype.as_bytes())
    }

    /// The parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// let mt = parse_net::parse_media_type(b"text/plain; charset=utf-8; format=flowed")?;
    /// assert_eq!(mt.params().len(), 2);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn params(&self) -> Params<'a> {
        self.params
    }

    /// The value of the parameter `name` (ASCII case-insensitive).
    ///
    /// # Examples
    ///
    /// ```
    /// let mt = parse_net::parse_media_type(b"text/plain; format=flowed")?;
    /// assert_eq!(mt.param("Format").and_then(|w| w.as_str()), Some("flowed"));
    /// assert!(mt.param("delsp").is_none());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn param(&self, name: &str) -> Option<Word<'a>> {
        self.params.get(name)
    }

    /// The `charset` parameter. Compare it case-insensitively.
    ///
    /// # Examples
    ///
    /// ```
    /// let mt = parse_net::parse_media_type(b"text/html; charset=\"UTF-8\"")?;
    /// assert!(mt.charset().is_some_and(|c| c.eq_ignore_ascii_case(b"utf-8")));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn charset(&self) -> Option<Word<'a>> {
        self.params.get("charset")
    }

    /// The `boundary` parameter, validated by RFC 2046 section 5.1.1: 1 to 70
    /// `bchars`, the last not a space. `Ok(None)` when absent.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidBoundary`], with the offset inside the boundary
    /// value.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::parse_media_type;
    ///
    /// let mt = parse_media_type(b"multipart/form-data; boundary=\"a b\"")?;
    /// assert_eq!(mt.boundary()?.map(|b| b.as_bytes()), Some(&b"a b"[..]));
    /// assert_eq!(parse_media_type(b"text/plain")?.boundary()?, None);
    /// assert!(parse_media_type(b"multipart/mixed; boundary=\"ab \"")?.boundary().is_err());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn boundary(&self) -> Result<Option<Boundary<'a>>> {
        let Some(word) = self.params.get("boundary") else {
            return Ok(None);
        };
        let bytes = match word {
            Word::Token(t) => t,
            // `\` is not a bchar, so a quoted boundary cannot carry escapes.
            Word::Quoted(q) if q.has_escapes() => {
                let at = q.raw().iter().position(|&b| b == b'\\').unwrap_or(0);
                return err(ErrorKind::InvalidBoundary, at);
            }
            Word::Quoted(q) => q.raw(),
        };
        if bytes.is_empty() {
            return err(ErrorKind::InvalidBoundary, 0);
        }
        if let Some(at) = bytes
            .iter()
            .position(|&b| !(class::is_bchar_nospace(b) || b == b' '))
        {
            return err(ErrorKind::InvalidBoundary, at);
        }
        if bytes.len() > 70 {
            return err(ErrorKind::InvalidBoundary, 70);
        }
        if bytes.last() == Some(&b' ') {
            return err(ErrorKind::InvalidBoundary, bytes.len() - 1);
        }
        Ok(Some(Boundary(bytes)))
    }

    /// Whether this is `application/json` or has the `+json` suffix.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::parse_media_type;
    ///
    /// assert!(parse_media_type(b"application/json")?.is_json());
    /// assert!(parse_media_type(b"application/problem+json")?.is_json());
    /// assert!(!parse_media_type(b"text/json")?.is_json());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn is_json(&self) -> bool {
        self.is("application", "json")
            || self
                .suffix()
                .is_some_and(|s| s.eq_ignore_ascii_case(b"json"))
    }

    /// Whether this is `application/x-www-form-urlencoded`.
    ///
    /// # Examples
    ///
    /// ```
    /// let mt = parse_net::parse_media_type(b"application/x-www-form-urlencoded; charset=utf-8")?;
    /// assert!(mt.is_form_urlencoded());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn is_form_urlencoded(&self) -> bool {
        self.is("application", "x-www-form-urlencoded")
    }

    /// Whether this is `multipart/form-data`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::parse_media_type;
    ///
    /// assert!(parse_media_type(b"multipart/form-data; boundary=x")?.is_multipart_form_data());
    /// assert!(!parse_media_type(b"multipart/mixed; boundary=x")?.is_multipart_form_data());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn is_multipart_form_data(&self) -> bool {
        self.is("multipart", "form-data")
    }

    /// Writes the media type with the type, subtype, and parameter names in
    /// lowercase and the values as sent, separated by `; `.
    ///
    /// # Errors
    ///
    /// [`WriteError::Full`]; nothing is written when the sink reports its
    /// room.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{parse_media_type, SliceSink};
    ///
    /// let mt = parse_media_type(b"Text/HTML;Charset=\"UTF-8\"")?;
    /// let mut buf = [0u8; 64];
    /// let mut out = SliceSink::new(&mut buf);
    /// mt.write_canonical(&mut out).expect("room");
    /// assert_eq!(out.written(), b"text/html; charset=\"UTF-8\"");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn write_canonical(&self, out: &mut impl Sink) -> core::result::Result<(), WriteError> {
        let mut len = self.type_.len() + 1 + self.subtype.len();
        for p in self.params.iter() {
            len = len.saturating_add(3 + p.name.len() + raw_word_len(&p.value));
        }
        reserve(out, len)?;
        put_lower(self.type_, out)?;
        out.put(b"/")?;
        put_lower(self.subtype, out)?;
        for p in self.params.iter() {
            out.put(b"; ")?;
            put_lower(p.name, out)?;
            out.put(b"=")?;
            match p.value {
                Word::Token(t) => out.put(t)?,
                Word::Quoted(q) => {
                    out.put(b"\"")?;
                    out.put(q.raw())?;
                    out.put(b"\"")?;
                }
            }
        }
        Ok(())
    }
}

/// The length of a word written as it was sent.
fn raw_word_len(w: &Word<'_>) -> usize {
    match w {
        Word::Token(t) => t.len(),
        Word::Quoted(q) => q.raw().len() + 2,
    }
}

/// Writes `s` in ASCII lowercase, through a small stack buffer.
fn put_lower(s: &[u8], out: &mut impl Sink) -> core::result::Result<(), WriteError> {
    let mut buf = [0u8; 64];
    for chunk in s.chunks(buf.len()) {
        let dst = buf.get_mut(..chunk.len()).unwrap_or(&mut []);
        for (d, &c) in dst.iter_mut().zip(chunk) {
            *d = c.to_ascii_lowercase();
        }
        out.put(dst)?;
    }
    Ok(())
}

/// A validated multipart boundary, unquoted.
///
/// # Examples
///
/// ```
/// let mt = parse_net::parse_media_type(b"multipart/mixed; boundary=gc0p4Jq0M2Yt08j34c0p")?;
/// assert_eq!(mt.boundary()?.map(|b| b.as_bytes()), Some(&b"gc0p4Jq0M2Yt08j34c0p"[..]));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Boundary<'a>(&'a [u8]);

impl<'a> Boundary<'a> {
    /// The boundary bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// let mt = parse_net::parse_media_type(b"multipart/mixed; boundary=\"simple boundary\"")?;
    /// assert_eq!(mt.boundary()?.map(|b| b.as_bytes()), Some(&b"simple boundary"[..]));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use std::{vec, vec::Vec};

    use super::*;
    use crate::write::SliceSink;

    fn mt(s: &[u8]) -> Result<MediaType<'_>> {
        parse_media_type(s)
    }

    #[test]
    fn test_media_type_edge_cases() {
        assert!(mt(b"text/html").unwrap().is("text", "html"));
        assert!(mt(b"TEXT/HTML").unwrap().essence_is("text/html"));
        assert!(mt(b"text/html;").unwrap().params().is_empty());
        assert!(mt(b"text/html ;charset=utf-8").unwrap().charset().is_some());
        assert!(mt(b" text/html \t").is_ok());
        let e = mt(b"text/ html").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidMediaType, 5));
        let e = mt(b"text /html").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidMediaType, 4));
        assert_eq!(
            mt(b"text/").unwrap_err().kind(),
            ErrorKind::InvalidMediaType
        );
        assert_eq!(
            mt(b"/html").unwrap_err().kind(),
            ErrorKind::InvalidMediaType
        );
        assert_eq!(mt(b"").unwrap_err().kind(), ErrorKind::InvalidMediaType);
        assert_eq!(mt(b"text").unwrap_err().kind(), ErrorKind::InvalidMediaType);
        assert_eq!(mt(b"*/*").unwrap_err().kind(), ErrorKind::Wildcard);
        let e = mt(b"text/*").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::Wildcard, 5));
        assert_eq!(
            mt(b"text/html x").unwrap_err().kind(),
            ErrorKind::InvalidMediaType
        );
        assert_eq!(mt(b"text/html\r").unwrap_err().kind(), ErrorKind::BareCr);
        assert_eq!(
            mt(b"text/html;a=b\nc").unwrap_err().kind(),
            ErrorKind::LineFeed
        );
        let e = mt(b"text/html; charset=a; Charset=b").unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::DuplicateParameter, 22));
    }

    #[test]
    fn test_media_type_suffix_and_predicates() {
        let v = mt(b"application/vnd.api+json").unwrap();
        assert_eq!(v.suffix(), Some(&b"json"[..]));
        assert!(v.is_json());
        assert!(mt(b"application/json").unwrap().is_json());
        assert!(!mt(b"application/jsonx").unwrap().is_json());
        assert_eq!(mt(b"application/a+").unwrap().suffix(), None);
        assert!(
            mt(b"application/x-www-form-urlencoded")
                .unwrap()
                .is_form_urlencoded()
        );
        assert!(!mt(b"text/html").unwrap().essence_is("texthtml"));
    }

    fn boundary(s: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(mt(s)?.boundary()?.map(|b| b.as_bytes().to_vec()))
    }

    #[test]
    fn test_boundary_rfc2046_rules() {
        assert_eq!(boundary(b"multipart/form-data").unwrap(), None);
        assert_eq!(
            boundary(b"multipart/form-data; boundary=")
                .unwrap_err()
                .kind(),
            ErrorKind::MissingValue
        );
        assert_eq!(
            boundary(b"multipart/form-data; boundary=\"\"")
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidBoundary
        );
        let seventy = vec![b'a'; 70];
        let mut v = b"multipart/mixed; boundary=".to_vec();
        v.extend_from_slice(&seventy);
        assert_eq!(boundary(&v).unwrap(), Some(seventy));
        v.push(b'a');
        assert_eq!(boundary(&v).unwrap_err().kind(), ErrorKind::InvalidBoundary);
        assert_eq!(
            boundary(b"multipart/mixed; boundary=\"ab \"")
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidBoundary
        );
        assert_eq!(
            boundary(b"multipart/mixed; boundary=\"a b\"").unwrap(),
            Some(b"a b".to_vec())
        );
        assert_eq!(
            boundary(b"multipart/mixed; boundary=\"a\\\\b\"")
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidBoundary
        );
        assert_eq!(
            boundary(b"multipart/mixed; boundary=a*b")
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidBoundary
        );
        assert_eq!(
            mt(b"multipart/mixed; boundary=a; boundary=b")
                .unwrap_err()
                .kind(),
            ErrorKind::DuplicateParameter
        );
    }

    #[test]
    fn test_media_write_refuses_bad_names_and_round_trips() {
        let mut buf = [0u8; 128];
        let mut out = SliceSink::new(&mut buf);
        assert_eq!(write("text", "*", &[], &mut out), Err(WriteError::NotToken));
        assert_eq!(
            write("te xt", "a", &[], &mut out),
            Err(WriteError::NotToken)
        );
        assert_eq!(
            write("a", "b", &[("x y", "1")], &mut out),
            Err(WriteError::NotToken)
        );
        assert_eq!(
            write("a", "b", &[("x", "1\r\n")], &mut out),
            Err(WriteError::Forbidden { at: 1 })
        );
        assert_eq!(
            write("a", "b", &[("x", "1"), ("X", "2")], &mut out),
            Err(WriteError::DuplicateName)
        );
        assert!(out.is_empty());
        write("a", "b", &[("x", "1 2"), ("y", "")], &mut out).unwrap();
        let back = mt(out.written()).unwrap();
        assert!(back.param("x").unwrap().eq_bytes(b"1 2"));
        assert!(back.param("y").unwrap().is_empty());
    }

    #[test]
    fn test_write_canonical_lowercases_names_only() {
        let v = mt(b"TEXT/Plain;  FORMAT=Flowed;x=\"A\\\"B\"").unwrap();
        let mut buf = [0u8; 64];
        let mut out = SliceSink::new(&mut buf);
        v.write_canonical(&mut out).unwrap();
        assert_eq!(out.written(), b"text/plain; format=Flowed; x=\"A\\\"B\"");
        let mut small = [0u8; 4];
        let mut out = SliceSink::new(&mut small);
        assert_eq!(v.write_canonical(&mut out), Err(WriteError::Full));
        assert!(out.is_empty());
    }
}
