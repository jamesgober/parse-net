//! RFC 9651 section 4.1: canonical serialization, as a streaming writer.

use super::{BareItem, parse::INTEGER_MAX};
use crate::{
    class,
    error::WriteError,
    write::{CountSink, Sink, reserve, write_decimal_u64},
};

type WResult<T> = core::result::Result<T, WriteError>;

/// What the writer produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Item,
    List,
    Dictionary,
}

/// Where the writer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// Nothing written yet.
    Empty,
    /// After a member (an item or a closed inner list): its parameters may
    /// follow.
    Member,
    /// After a dictionary key with no value yet (Boolean true so far).
    Key,
    /// Inside an inner list, before its first item.
    Inner,
    /// Inside an inner list, after an item: its parameters may follow.
    InnerItem,
}

/// A value to write after the separator.
#[derive(Clone, Copy)]
enum Val<'v> {
    Bare(&'v BareItem<'v>),
    Integer(i64),
    Decimal(i64),
    String(&'v str),
    Token(&'v str),
    Boolean(bool),
    Date(i64),
    Display(&'v str),
}

/// A canonical Structured Field writer (RFC 9651 section 4.1).
///
/// Calls must follow the structure: for an Item, one bare item and its
/// parameters; for a List, members (bare items or inner lists), each with
/// parameters; for a Dictionary, a key before each member. A dictionary
/// member whose value is Boolean true is written as its key alone. Each call
/// reserves its own room, so a call that fails writes nothing; the earlier
/// calls' output stays in the sink, and a caller that gets an error discards
/// the field.
///
/// # Examples
///
/// ```
/// use parse_net::{sfv::{BareItem, Writer}, SliceSink};
///
/// let mut buf = [0u8; 64];
/// let mut out = SliceSink::new(&mut buf);
/// let mut w = Writer::dictionary(&mut out);
/// w.key("u")?.integer(1)?;
/// w.key("i")?.boolean(true)?;
/// w.key("lang")?.open_inner_list()?.token("en")?.token("de")?.close_inner_list()?;
/// w.key("q")?.decimal(500)?.param("x", &BareItem::Token("a"))?;
/// w.finish()?;
/// assert_eq!(out.written(), b"u=1, i, lang=(en de), q=0.5;x=a");
/// # Ok::<(), parse_net::WriteError>(())
/// ```
#[derive(Debug)]
pub struct Writer<'s, S: Sink> {
    out: &'s mut S,
    kind: Kind,
    state: State,
    /// A parameter key was written by `param_key`; the next value call is
    /// its value.
    pending: bool,
}

impl<'s, S: Sink> Writer<'s, S> {
    /// A writer for an Item.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::item(&mut out);
    /// w.integer(5)?.param_key("a")?.token("b")?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"5;a=b");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn item(out: &'s mut S) -> Self {
        Self {
            out,
            kind: Kind::Item,
            state: State::Empty,
            pending: false,
        }
    }

    /// A writer for a List.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::list(&mut out);
    /// w.token("a")?.token("b")?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"a, b");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn list(out: &'s mut S) -> Self {
        Self {
            out,
            kind: Kind::List,
            state: State::Empty,
            pending: false,
        }
    }

    /// A writer for a Dictionary.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::dictionary(&mut out);
    /// w.key("a")?.integer(1)?;
    /// w.key("b")?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"a=1, b");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn dictionary(out: &'s mut S) -> Self {
        Self {
            out,
            kind: Kind::Dictionary,
            state: State::Empty,
            pending: false,
        }
    }

    /// Writes `prefix`, then `key`, then `=` and `value` when both are given
    /// (or `value` alone): sized first, so an error writes nothing.
    fn emit(&mut self, prefix: &[u8], key: Option<&str>, value: Option<Val<'_>>) -> WResult<()> {
        let mut count = CountSink::new();
        put(prefix, key, value, &mut count)?;
        reserve(&*self.out, count.count())?;
        put(prefix, key, value, &mut *self.out)
    }

    /// The next member value (a bare item), according to the state.
    fn value(&mut self, v: Val<'_>) -> WResult<&mut Self> {
        if self.pending {
            if !matches!(v, Val::Boolean(true) | Val::Bare(BareItem::Boolean(true))) {
                self.emit(b"=", None, Some(v))?;
            }
            self.pending = false;
            return Ok(self);
        }
        match (self.kind, self.state) {
            (Kind::Item, State::Empty) => self.emit(b"", None, Some(v))?,
            (Kind::List, State::Empty) => self.emit(b"", None, Some(v))?,
            (Kind::List, State::Member) => self.emit(b", ", None, Some(v))?,
            (Kind::Dictionary, State::Key) => {
                // A Boolean true value is the key alone.
                if !matches!(v, Val::Boolean(true) | Val::Bare(BareItem::Boolean(true))) {
                    self.emit(b"=", None, Some(v))?;
                }
            }
            (_, State::Inner) => {
                self.emit(b"", None, Some(v))?;
                self.state = State::InnerItem;
                return Ok(self);
            }
            (_, State::InnerItem) => {
                self.emit(b" ", None, Some(v))?;
                return Ok(self);
            }
            _ => return Err(WriteError::InvalidSequence),
        }
        self.state = State::Member;
        Ok(self)
    }

    /// Writes a bare item.
    ///
    /// # Errors
    ///
    /// As the typed methods; [`WriteError::InvalidSequence`] out of order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::{BareItem, Writer}, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::list(&mut out);
    /// w.bare(&BareItem::Token("x"))?.bare(&BareItem::Integer(-2))?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"x, -2");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn bare(&mut self, b: &BareItem<'_>) -> WResult<&mut Self> {
        self.value(Val::Bare(b))
    }

    /// Writes an Integer.
    ///
    /// # Errors
    ///
    /// [`WriteError::OutOfRange`] beyond 15 digits; [`WriteError::Full`];
    /// [`WriteError::InvalidSequence`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::list(&mut out);
    /// w.integer(-42)?;
    /// assert!(w.integer(1_000_000_000_000_000).is_err());
    /// w.finish()?;
    /// assert_eq!(out.written(), b"-42");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn integer(&mut self, v: i64) -> WResult<&mut Self> {
        self.value(Val::Integer(v))
    }

    /// Writes a Decimal given in thousandths, with the shortest fractional
    /// part (`1.5`, and `1.0` for a whole number).
    ///
    /// # Errors
    ///
    /// [`WriteError::OutOfRange`] beyond 12 integer digits;
    /// [`WriteError::Full`]; [`WriteError::InvalidSequence`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::list(&mut out);
    /// w.decimal(1500)?.decimal(2000)?.decimal(-125)?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"1.5, 2.0, -0.125");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn decimal(&mut self, thousandths: i64) -> WResult<&mut Self> {
        self.value(Val::Decimal(thousandths))
    }

    /// Writes a String, escaping only `"` and `\`.
    ///
    /// # Errors
    ///
    /// [`WriteError::Forbidden`] for a byte outside `%x20-7E` (use
    /// [`display_string`](Self::display_string) for other text);
    /// [`WriteError::Full`]; [`WriteError::InvalidSequence`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::item(&mut out);
    /// w.string("say \"hi\"")?;
    /// w.finish()?;
    /// assert_eq!(out.written(), br#""say \"hi\"""#);
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn string(&mut self, s: &str) -> WResult<&mut Self> {
        self.value(Val::String(s))
    }

    /// Writes a Token.
    ///
    /// # Errors
    ///
    /// [`WriteError::NotToken`]; [`WriteError::Full`];
    /// [`WriteError::InvalidSequence`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::list(&mut out);
    /// w.token("gzip")?;
    /// assert!(w.token("a b").is_err());
    /// w.finish()?;
    /// assert_eq!(out.written(), b"gzip");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn token(&mut self, t: &str) -> WResult<&mut Self> {
        self.value(Val::Token(t))
    }

    /// Writes a Boolean (`?1` or `?0`).
    ///
    /// # Errors
    ///
    /// [`WriteError::Full`]; [`WriteError::InvalidSequence`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::list(&mut out);
    /// w.boolean(true)?.boolean(false)?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"?1, ?0");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn boolean(&mut self, b: bool) -> WResult<&mut Self> {
        self.value(Val::Boolean(b))
    }

    /// Writes a Date: `@` and the seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// [`WriteError::OutOfRange`] outside years 1 to 9999 (D-030);
    /// [`WriteError::Full`]; [`WriteError::InvalidSequence`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::item(&mut out);
    /// w.date(1_659_578_233)?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"@1659578233");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn date(&mut self, secs: i64) -> WResult<&mut Self> {
        self.value(Val::Date(secs))
    }

    /// Writes a Display String: `%"`, the text with `%`, `"`, and every byte
    /// outside `%x20-7E` as lowercase `%xx`, then `"`.
    ///
    /// # Errors
    ///
    /// [`WriteError::Full`]; [`WriteError::InvalidSequence`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::item(&mut out);
    /// w.display_string("caf\u{e9}")?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"%\"caf%c3%a9\"");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn display_string(&mut self, s: &str) -> WResult<&mut Self> {
        self.value(Val::Display(s))
    }

    /// Writes a parameter of the last item or inner list. A Boolean true
    /// value is written as the key alone.
    ///
    /// # Errors
    ///
    /// [`WriteError::NotToken`] for a key that is not
    /// `( lcalpha / "*" ) *( lcalpha / DIGIT / "_" / "-" / "." / "*" )`;
    /// the value's errors; [`WriteError::InvalidSequence`] before any item;
    /// [`WriteError::Full`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::{BareItem, Writer}, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::item(&mut out);
    /// w.token("a")?.param("q", &BareItem::Integer(1))?.param("x", &BareItem::Boolean(true))?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"a;q=1;x");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn param(&mut self, key: &str, v: &BareItem<'_>) -> WResult<&mut Self> {
        if self.pending || !matches!(self.state, State::Member | State::Key | State::InnerItem) {
            return Err(WriteError::InvalidSequence);
        }
        let value = (!matches!(v, BareItem::Boolean(true))).then_some(Val::Bare(v));
        self.emit(b";", Some(key), value)?;
        if self.state == State::Key {
            self.state = State::Member;
        }
        Ok(self)
    }

    /// Writes the key of a parameter of the last item or inner list; the next
    /// value call ([`string`](Self::string), [`integer`](Self::integer), and
    /// the others) writes its value, and a Boolean true writes nothing more.
    /// For values that are not already a parsed [`BareItem`].
    ///
    /// # Errors
    ///
    /// As [`param`](Self::param).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::item(&mut out);
    /// w.token("text")?.param_key("lang")?.string("en \"GB\"")?.param_key("x")?.boolean(true)?;
    /// w.finish()?;
    /// assert_eq!(out.written(), br#"text;lang="en \"GB\"";x"#);
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn param_key(&mut self, key: &str) -> WResult<&mut Self> {
        if self.pending || !matches!(self.state, State::Member | State::Key | State::InnerItem) {
            return Err(WriteError::InvalidSequence);
        }
        self.emit(b";", Some(key), None)?;
        if self.state == State::Key {
            self.state = State::Member;
        }
        self.pending = true;
        Ok(self)
    }

    /// Writes a dictionary key; its value follows (none means Boolean true).
    ///
    /// # Errors
    ///
    /// [`WriteError::NotToken`] for an invalid key;
    /// [`WriteError::InvalidSequence`] outside a dictionary or inside an
    /// inner list; [`WriteError::Full`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::dictionary(&mut out);
    /// w.key("a")?;
    /// w.key("b")?.integer(2)?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"a, b=2");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn key(&mut self, key: &str) -> WResult<&mut Self> {
        if self.pending {
            return Err(WriteError::InvalidSequence);
        }
        let prefix: &[u8] = match (self.kind, self.state) {
            (Kind::Dictionary, State::Empty) => b"",
            (Kind::Dictionary, State::Member | State::Key) => b", ",
            _ => return Err(WriteError::InvalidSequence),
        };
        self.emit(prefix, Some(key), None)?;
        self.state = State::Key;
        Ok(self)
    }

    /// Opens an inner list as the next list member or dictionary value.
    ///
    /// # Errors
    ///
    /// [`WriteError::InvalidSequence`] in an Item writer, inside an inner
    /// list, or in a dictionary before a key; [`WriteError::Full`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::list(&mut out);
    /// w.open_inner_list()?.token("a")?.token("b")?.close_inner_list()?;
    /// w.token("c")?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"(a b), c");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn open_inner_list(&mut self) -> WResult<&mut Self> {
        if self.pending {
            return Err(WriteError::InvalidSequence);
        }
        let prefix: &[u8] = match (self.kind, self.state) {
            (Kind::List, State::Empty) => b"(",
            (Kind::List, State::Member) => b", (",
            (Kind::Dictionary, State::Key) => b"=(",
            _ => return Err(WriteError::InvalidSequence),
        };
        self.emit(prefix, None, None)?;
        self.state = State::Inner;
        Ok(self)
    }

    /// Closes the open inner list; its parameters may follow.
    ///
    /// # Errors
    ///
    /// [`WriteError::InvalidSequence`] with no inner list open;
    /// [`WriteError::Full`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::{BareItem, Writer}, SliceSink};
    ///
    /// let mut buf = [0u8; 32];
    /// let mut out = SliceSink::new(&mut buf);
    /// let mut w = Writer::list(&mut out);
    /// w.open_inner_list()?.integer(1)?.close_inner_list()?.param("q", &BareItem::Integer(9))?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"(1);q=9");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn close_inner_list(&mut self) -> WResult<&mut Self> {
        if self.pending || !matches!(self.state, State::Inner | State::InnerItem) {
            return Err(WriteError::InvalidSequence);
        }
        self.emit(b")", None, None)?;
        self.state = State::Member;
        Ok(self)
    }

    /// Ends the field.
    ///
    /// # Errors
    ///
    /// [`WriteError::InvalidSequence`] with an inner list open, a
    /// parameter key without its value, or with nothing written (an empty List or Dictionary is not serialized at
    /// all: omit the field, RFC 9651 section 4.1).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Writer, SliceSink};
    ///
    /// let mut buf = [0u8; 8];
    /// let mut out = SliceSink::new(&mut buf);
    /// assert!(Writer::list(&mut out).finish().is_err());
    /// let mut w = Writer::list(&mut out);
    /// w.token("a")?;
    /// w.finish()?;
    /// assert_eq!(out.written(), b"a");
    /// # Ok::<(), parse_net::WriteError>(())
    /// ```
    pub fn finish(self) -> WResult<()> {
        if self.pending {
            return Err(WriteError::InvalidSequence);
        }
        match self.state {
            State::Member | State::Key => Ok(()),
            State::Empty | State::Inner | State::InnerItem => Err(WriteError::InvalidSequence),
        }
    }
}

/// One byte of a Display String in canonical form: `%`, `"`, and every byte
/// outside `%x20-7E` as lowercase `%xx`.
fn put_display_byte(b: u8, out: &mut impl Sink) -> WResult<()> {
    if b == b'%' || b == b'"' || !(0x20..=0x7e).contains(&b) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let hi = HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0');
        let lo = HEX.get(usize::from(b & 0xf)).copied().unwrap_or(b'0');
        out.put(&[b'%', hi, lo])?;
    } else {
        out.put(&[b])?;
    }
    Ok(())
}

/// The value of a base64 symbol (validated at parse).
const fn b64_value(c: u8) -> u8 {
    match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    }
}

/// The base64 symbol for a 6-bit value.
const fn b64_symbol(v: u8) -> u8 {
    match v {
        0..=25 => b'A' + v,
        26..=51 => b'a' + (v - 26),
        52..=61 => b'0' + (v - 52),
        62 => b'+',
        _ => b'/',
    }
}

fn is_key(k: &[u8]) -> bool {
    matches!(k.first(), Some(&b) if class::is_sf_key_start(b))
        && k.iter().skip(1).all(|&b| class::is_sf_key_char(b))
}

fn is_sf_token(t: &[u8]) -> bool {
    matches!(t.first(), Some(&b) if b == b'*' || b.is_ascii_alphabetic())
        && t.iter().skip(1).all(|&b| class::is_sf_token_char(b))
}

fn put(
    prefix: &[u8],
    key: Option<&str>,
    value: Option<Val<'_>>,
    out: &mut impl Sink,
) -> WResult<()> {
    out.put(prefix)?;
    if let Some(k) = key {
        if !is_key(k.as_bytes()) {
            return Err(WriteError::NotToken);
        }
        out.put(k.as_bytes())?;
        if value.is_some() {
            out.put(b"=")?;
        }
    }
    match value {
        None => Ok(()),
        Some(v) => put_value(v, out),
    }
}

fn put_integer(v: i64, out: &mut impl Sink) -> WResult<()> {
    if !(-INTEGER_MAX..=INTEGER_MAX).contains(&v) {
        return Err(WriteError::OutOfRange);
    }
    if v < 0 {
        out.put(b"-")?;
    }
    write_decimal_u64(v.unsigned_abs(), out)
}

fn put_value(v: Val<'_>, out: &mut impl Sink) -> WResult<()> {
    match v {
        Val::Integer(i) => put_integer(i, out),
        Val::Decimal(t) => {
            if !(-INTEGER_MAX..=INTEGER_MAX).contains(&t) {
                return Err(WriteError::OutOfRange);
            }
            if t < 0 {
                out.put(b"-")?;
            }
            let a = t.unsigned_abs();
            write_decimal_u64(a / 1000, out)?;
            out.put(b".")?;
            let frac = a % 1000;
            let digits = [
                b'0' + (frac / 100) as u8,
                b'0' + (frac / 10 % 10) as u8,
                b'0' + (frac % 10) as u8,
            ];
            let keep = if frac % 100 == 0 {
                1
            } else if frac % 10 == 0 {
                2
            } else {
                3
            };
            out.put(digits.get(..keep).unwrap_or(&[]))?;
            Ok(())
        }
        Val::String(s) => {
            if let Some(at) = s.bytes().position(|b| !(0x20..=0x7e).contains(&b)) {
                return Err(WriteError::forbidden(at));
            }
            out.put(b"\"")?;
            for chunk in s.as_bytes().split_inclusive(|&b| b == b'"' || b == b'\\') {
                match chunk.split_last() {
                    Some((&last, head)) if last == b'"' || last == b'\\' => {
                        out.put(head)?;
                        out.put(b"\\")?;
                        out.put(&[last])?;
                    }
                    _ => out.put(chunk)?,
                }
            }
            out.put(b"\"")?;
            Ok(())
        }
        Val::Token(t) => {
            if !is_sf_token(t.as_bytes()) {
                return Err(WriteError::NotToken);
            }
            out.put(t.as_bytes())?;
            Ok(())
        }
        Val::Boolean(b) => {
            out.put(if b { b"?1" } else { b"?0" })?;
            Ok(())
        }
        Val::Date(d) => {
            if d < crate::HttpDate::MIN.unix() || d > crate::HttpDate::MAX.unix() {
                return Err(WriteError::OutOfRange);
            }
            out.put(b"@")?;
            put_integer(d, out)
        }
        Val::Display(s) => {
            out.put(b"%\"")?;
            for &b in s.as_bytes() {
                put_display_byte(b, out)?;
            }
            out.put(b"\"")?;
            Ok(())
        }
        Val::Bare(b) => match *b {
            BareItem::Integer(i) => put_integer(i, out),
            BareItem::Decimal(d) => put_value(Val::Decimal(d.thousandths()), out),
            BareItem::String(s) => {
                // Validated at parse: only `\"` and `\\` escapes.
                out.put(b"\"")?;
                out.put(s.raw().as_bytes())?;
                out.put(b"\"")?;
                Ok(())
            }
            BareItem::Token(t) => put_value(Val::Token(t), out),
            BareItem::ByteSeq(s) => {
                let body: &[u8] = s.raw().split(|&b| b == b'=').next().unwrap_or(&[]);
                out.put(b":")?;
                // Canonical base64 has zero pad bits: the last symbol of a
                // partial quantum keeps only the bits that carry data.
                let (pad, mask): (&[u8], u8) = match body.len() % 4 {
                    2 => (b"==", 0x30),
                    3 => (b"=", 0x3c),
                    _ => (b"", 0x3f),
                };
                if let Some((&last, head)) = body.split_last() {
                    out.put(head)?;
                    out.put(&[b64_symbol(b64_value(last) & mask)])?;
                }
                out.put(pad)?;
                out.put(b":")?;
                Ok(())
            }
            BareItem::Boolean(v) => put_value(Val::Boolean(v), out),
            BareItem::Date(d) => put_value(Val::Date(d), out),
            BareItem::DisplayString(s) => {
                // Validated at parse: lowercase `%xx` and printable ASCII.
                // Each byte is decoded and written in canonical form, so an
                // over-encoded `%61` comes out as `a`.
                out.put(b"%\"")?;
                let raw = s.raw();
                let mut i = 0usize;
                while let Some(&b) = raw.get(i) {
                    let byte = if b == b'%' {
                        let hi = raw
                            .get(i + 1)
                            .copied()
                            .and_then(class::hex_value)
                            .unwrap_or(0);
                        let lo = raw
                            .get(i + 2)
                            .copied()
                            .and_then(class::hex_value)
                            .unwrap_or(0);
                        i += 3;
                        (hi << 4) | lo
                    } else {
                        i += 1;
                        b
                    };
                    put_display_byte(byte, out)?;
                }
                out.put(b"\"")?;
                Ok(())
            }
        },
    }
}

#[cfg(test)]
// The builder methods return `&mut Self` for chaining; a test that does
// not chain drops it.
#[allow(unused_results)]
mod tests {
    use super::*;
    use crate::{SliceSink, sfv};

    fn item(f: impl FnOnce(&mut Writer<'_, SliceSink<'_>>) -> WResult<()>) -> std::string::String {
        let mut buf = [0u8; 256];
        let mut out = SliceSink::new(&mut buf);
        let mut w = Writer::item(&mut out);
        f(&mut w).unwrap();
        w.finish().unwrap();
        std::string::String::from_utf8(out.written().to_vec()).unwrap()
    }

    #[test]
    fn test_writer_bare_items_canonical() {
        assert_eq!(
            item(|w| w.integer(-999_999_999_999_999).map(|_| ())),
            "-999999999999999"
        );
        assert_eq!(item(|w| w.decimal(1500).map(|_| ())), "1.5");
        assert_eq!(item(|w| w.decimal(-1000).map(|_| ())), "-1.0");
        assert_eq!(item(|w| w.decimal(-5).map(|_| ())), "-0.005");
        assert_eq!(item(|w| w.decimal(1230).map(|_| ())), "1.23");
        assert_eq!(item(|w| w.string("a\"b\\c").map(|_| ())), "\"a\\\"b\\\\c\"");
        assert_eq!(item(|w| w.token("*foo/bar:1").map(|_| ())), "*foo/bar:1");
        assert_eq!(item(|w| w.boolean(false).map(|_| ())), "?0");
        assert_eq!(item(|w| w.date(0).map(|_| ())), "@0");
        assert_eq!(
            item(|w| w.display_string("f\u{fc}%\"").map(|_| ())),
            "%\"f%c3%bc%25%22\""
        );
        let parsed = sfv::parse_item(b":YQ:").unwrap();
        assert_eq!(item(|w| w.bare(&parsed.bare).map(|_| ())), ":YQ==:");
        // Non-zero pad bits are accepted on parse and cleared on write.
        let parsed = sfv::parse_item(b":iZ==:").unwrap();
        assert_eq!(item(|w| w.bare(&parsed.bare).map(|_| ())), ":iQ==:");
        let parsed = sfv::parse_item(b":YWJ=:").unwrap();
        assert_eq!(item(|w| w.bare(&parsed.bare).map(|_| ())), ":YWI=:");
        let parsed = sfv::parse_item(b"::").unwrap();
        assert_eq!(item(|w| w.bare(&parsed.bare).map(|_| ())), "::");
    }

    #[test]
    fn test_writer_refusals_write_nothing() {
        let mut buf = [0u8; 64];
        let mut out = SliceSink::new(&mut buf);
        let mut w = Writer::item(&mut out);
        assert_eq!(
            w.integer(1_000_000_000_000_000).err(),
            Some(WriteError::OutOfRange)
        );
        assert_eq!(
            w.decimal(1_000_000_000_000_000).err(),
            Some(WriteError::OutOfRange)
        );
        assert_eq!(w.date(253_402_300_800).err(), Some(WriteError::OutOfRange));
        assert_eq!(
            w.string("caf\u{e9}").err(),
            Some(WriteError::Forbidden { at: 3 })
        );
        assert_eq!(
            w.string("a\nb").err(),
            Some(WriteError::Forbidden { at: 1 })
        );
        assert_eq!(w.token("1a").err(), Some(WriteError::NotToken));
        assert_eq!(w.token("").err(), Some(WriteError::NotToken));
        assert_eq!(
            w.param("a", &BareItem::Integer(1)).err(),
            Some(WriteError::InvalidSequence)
        );
        assert_eq!(w.key("a").err(), Some(WriteError::InvalidSequence));
        assert_eq!(w.open_inner_list().err(), Some(WriteError::InvalidSequence));
        w.integer(1).unwrap();
        assert_eq!(w.integer(2).err(), Some(WriteError::InvalidSequence));
        assert_eq!(
            w.param("A", &BareItem::Integer(1)).err(),
            Some(WriteError::NotToken)
        );
        assert_eq!(
            w.param("1a", &BareItem::Integer(1)).err(),
            Some(WriteError::NotToken)
        );
        w.finish().unwrap();
        assert_eq!(out.written(), b"1");
    }

    #[test]
    fn test_writer_list_and_inner_lists() {
        let mut buf = [0u8; 128];
        let mut out = SliceSink::new(&mut buf);
        let mut w = Writer::list(&mut out);
        w.token("a")
            .unwrap()
            .param("x", &BareItem::Boolean(true))
            .unwrap();
        w.open_inner_list().unwrap();
        assert_eq!(
            w.param("p", &BareItem::Integer(1)).err(),
            Some(WriteError::InvalidSequence)
        );
        w.integer(1)
            .unwrap()
            .param("q", &BareItem::Boolean(false))
            .unwrap()
            .integer(2)
            .unwrap();
        w.close_inner_list()
            .unwrap()
            .param("lvl", &BareItem::Integer(5))
            .unwrap();
        w.open_inner_list().unwrap().close_inner_list().unwrap();
        w.finish().unwrap();
        assert_eq!(out.written(), b"a;x, (1;q=?0 2);lvl=5, ()");
        assert!(sfv::parse_list(out.written()).is_ok());
    }

    #[test]
    fn test_writer_param_key_then_value() {
        let mut buf = [0u8; 64];
        let mut out = SliceSink::new(&mut buf);
        let mut w = Writer::list(&mut out);
        w.token("a")
            .unwrap()
            .param_key("s")
            .unwrap()
            .string("x y")
            .unwrap();
        assert_eq!(
            w.param_key("t").unwrap().key("k").err(),
            Some(WriteError::InvalidSequence)
        );
        assert_eq!(
            w.param("u", &BareItem::Integer(1)).err(),
            Some(WriteError::InvalidSequence)
        );
        w.decimal(250).unwrap();
        w.open_inner_list()
            .unwrap()
            .integer(1)
            .unwrap()
            .param_key("d")
            .unwrap()
            .display_string("\u{e9}")
            .unwrap();
        w.close_inner_list()
            .unwrap()
            .param_key("b")
            .unwrap()
            .boolean(true)
            .unwrap();
        w.finish().unwrap();
        assert_eq!(out.written(), br#"a;s="x y";t=0.25, (1;d=%"%c3%a9");b"#);
        let mut buf = [0u8; 16];
        let mut out = SliceSink::new(&mut buf);
        let mut w = Writer::item(&mut out);
        w.integer(1).unwrap().param_key("k").unwrap();
        assert_eq!(w.finish(), Err(WriteError::InvalidSequence));
    }

    #[test]
    fn test_writer_finish_refusals() {
        let mut buf = [0u8; 16];
        let mut out = SliceSink::new(&mut buf);
        assert_eq!(
            Writer::list(&mut out).finish(),
            Err(WriteError::InvalidSequence)
        );
        assert_eq!(
            Writer::dictionary(&mut out).finish(),
            Err(WriteError::InvalidSequence)
        );
        assert_eq!(
            Writer::item(&mut out).finish(),
            Err(WriteError::InvalidSequence)
        );
        let mut w = Writer::list(&mut out);
        w.open_inner_list().unwrap();
        assert_eq!(w.finish(), Err(WriteError::InvalidSequence));
        let mut w = Writer::dictionary(&mut out);
        assert_eq!(w.integer(1).err(), Some(WriteError::InvalidSequence));
        assert_eq!(w.open_inner_list().err(), Some(WriteError::InvalidSequence));
    }

    #[test]
    fn test_writer_dictionary_true_is_key_alone() {
        let mut buf = [0u8; 128];
        let mut out = SliceSink::new(&mut buf);
        let mut w = Writer::dictionary(&mut out);
        w.key("a").unwrap().boolean(true).unwrap();
        w.key("b").unwrap();
        w.key("c")
            .unwrap()
            .param("p", &BareItem::Integer(1))
            .unwrap();
        w.key("d").unwrap().boolean(false).unwrap();
        w.finish().unwrap();
        assert_eq!(out.written(), b"a, b, c;p=1, d=?0");
        assert!(sfv::parse_dictionary(out.written()).is_ok());
    }

    #[test]
    fn test_writer_full_writes_nothing_for_the_call() {
        let mut buf = [0u8; 4];
        let mut out = SliceSink::new(&mut buf);
        let mut w = Writer::item(&mut out);
        assert_eq!(w.string("abcd").err(), Some(WriteError::Full));
        w.token("ab").unwrap();
        assert_eq!(
            w.param("cd", &BareItem::Integer(1)).err(),
            Some(WriteError::Full)
        );
        w.finish().unwrap();
        assert_eq!(out.written(), b"ab");
    }
}
