//! Structured Field Values (RFC 9651): Items, Lists, and Dictionaries with
//! every bare item type, parsed into borrowed views.
//!
//! The parser follows RFC 9651 section 4.2 exactly, as a loop with explicit
//! state; inner lists cannot nest, so there is no recursion. A field is
//! accepted or refused as a whole, as section 4.2 requires. Every limit of
//! section 3 is enforced through [`Limits`], whose defaults meet each
//! minimum.
//!
//! # Examples
//!
//! ```
//! use parse_net::sfv::{self, BareItem, Member};
//!
//! let site = sfv::parse_item(b"same-origin")?;
//! assert_eq!(site.bare, BareItem::Token("same-origin"));
//!
//! let prio = sfv::parse_dictionary(b"u=1, i")?;
//! assert!(matches!(prio.get("u"), Some(Member::Item(i)) if i.bare == BareItem::Integer(1)));
//! assert!(matches!(prio.get("i"), Some(Member::Item(i)) if i.bare == BareItem::Boolean(true)));
//!
//! let list = sfv::parse_list(b"(\"foo\" \"bar\");lvl=5, abc;a=?0")?;
//! assert_eq!(list.len(), 2);
//! let Some(Member::InnerList(inner)) = list.iter().next() else { unreachable!() };
//! assert_eq!(inner.len(), 2);
//! # Ok::<(), parse_net::ParseError>(())
//! ```

#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub mod owned;
mod parse;
mod write;

pub use write::Writer;

use parse::{Cursor, Events, Nothing};

use crate::{
    error::{ErrorKind, ParseError, Result, err},
    limits::Limits,
};

/// Limits for walking text that was already validated: every bound at its
/// maximum, so a view never refuses what its parse accepted.
const RELAXED: Limits = Limits::DEFAULT
    .max_list_members(u16::MAX)
    .max_inner_list_members(u16::MAX)
    .max_params(u16::MAX)
    .max_dictionary_members(u16::MAX)
    .max_key_len(u16::MAX)
    .max_string_len(u16::MAX)
    .max_token_len(u16::MAX)
    .max_byte_seq_len(u32::MAX);

/// A bare item (RFC 9651 section 3.3).
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem};
///
/// assert_eq!(sfv::parse_item(b"42")?.bare, BareItem::Integer(42));
/// assert_eq!(sfv::parse_item(b"abc")?.bare, BareItem::Token("abc"));
/// assert!(matches!(sfv::parse_item(b"\"hi\"")?.bare, BareItem::String(s) if s.eq_str("hi")));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BareItem<'a> {
    /// An Integer, at most 15 digits.
    Integer(i64),
    /// A Decimal, in thousandths.
    Decimal(Decimal),
    /// A String.
    String(SfString<'a>),
    /// A Token (ASCII by construction).
    Token(&'a str),
    /// A Byte Sequence, still base64.
    ByteSeq(ByteSeq<'a>),
    /// A Boolean.
    Boolean(bool),
    /// A Date: seconds since the Unix epoch, within years 1 to 9999.
    Date(i64),
    /// A Display String, still percent-encoded.
    DisplayString(DisplayString<'a>),
}

/// A Decimal in thousandths: at most 12 integer and 3 fractional digits.
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem, Decimal};
///
/// assert_eq!(sfv::parse_item(b"-1.5")?.bare, BareItem::Decimal(Decimal::from_thousandths(-1500)?));
/// assert!(Decimal::from_thousandths(1_000_000_000_000_000).is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Decimal(pub(crate) i64);

impl Decimal {
    /// The decimal `t / 1000`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::OutOfRange`] beyond 12 integer digits.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::Decimal;
    ///
    /// assert_eq!(Decimal::from_thousandths(1500)?.thousandths(), 1500);
    /// assert!(Decimal::from_thousandths(1_000_000_000_000_000).is_err());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub const fn from_thousandths(t: i64) -> Result<Self> {
        if t > parse::INTEGER_MAX || t < -parse::INTEGER_MAX {
            return err(ErrorKind::OutOfRange, 0);
        }
        Ok(Self(t))
    }

    /// The value in thousandths.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let BareItem::Decimal(d) = sfv::parse_item(b"2.25")?.bare else { unreachable!() };
    /// assert_eq!(d.thousandths(), 2250);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn thousandths(self) -> i64 {
        self.0
    }
}

/// A String: the content between the quotes, only `\"` and `\\` escapes.
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem};
///
/// let BareItem::String(s) = sfv::parse_item(b"\"hello\"")?.bare else { unreachable!() };
/// assert!(s.eq_str("hello"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SfString<'a> {
    raw: &'a str,
    escapes: bool,
}

impl<'a> SfString<'a> {
    /// The content as sent, escapes included (ASCII by construction).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let BareItem::String(s) = sfv::parse_item(br#""a\"b""#)?.bare else { unreachable!() };
    /// assert_eq!(s.raw(), r#"a\"b"#);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn raw(&self) -> &'a str {
        self.raw
    }

    /// The value with no copy, when it has no escape.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let BareItem::String(s) = sfv::parse_item(b"\"plain\"")?.bare else { unreachable!() };
    /// assert_eq!(s.as_plain(), Some("plain"));
    /// let BareItem::String(e) = sfv::parse_item(br#""a\"b""#)?.bare else { unreachable!() };
    /// assert_eq!(e.as_plain(), None);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn as_plain(&self) -> Option<&'a str> {
        if self.escapes { None } else { Some(self.raw) }
    }

    fn bytes(&self) -> crate::text::Unescape<'a> {
        crate::text::Quoted::from_raw(self.raw.as_bytes(), self.escapes).bytes()
    }

    /// The length of the unescaped value.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let BareItem::String(s) = sfv::parse_item(br#""a\"b""#)?.bare else { unreachable!() };
    /// assert_eq!(s.raw().len(), 4);
    /// assert_eq!(s.unescaped_len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn unescaped_len(&self) -> usize {
        if self.escapes {
            self.bytes().count()
        } else {
            self.raw.len()
        }
    }

    /// Writes the unescaped value into `out` and returns it.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::BufferTooSmall`]; nothing is written.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let BareItem::String(s) = sfv::parse_item(b"\"a \\\"b\\\"\"")?.bare else { unreachable!() };
    /// let mut buf = [0u8; 8];
    /// assert_eq!(s.unescape_into(&mut buf)?, "a \"b\"");
    /// assert!(s.eq_str("a \"b\""));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn unescape_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str> {
        let len = self.unescaped_len();
        let Some(dst) = out.get_mut(..len) else {
            return err(ErrorKind::BufferTooSmall, 0);
        };
        for (d, b) in dst.iter_mut().zip(self.bytes()) {
            *d = b;
        }
        // ASCII in, ASCII out.
        core::str::from_utf8(dst).map_err(|_| ParseError::new(ErrorKind::InvalidUtf8, 0))
    }

    /// Whether the unescaped value equals `other`, with no buffer.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let BareItem::String(s) = sfv::parse_item(br#""a\"b""#)?.bare else { unreachable!() };
    /// assert!(s.eq_str("a\"b"));
    /// assert!(!s.eq_str(r#"a\"b"#));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn eq_str(&self, other: &str) -> bool {
        self.bytes().eq(other.bytes())
    }
}

/// A Byte Sequence: the base64 text between the colons.
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem};
///
/// let BareItem::ByteSeq(b) = sfv::parse_item(b":aGVsbG8=:")?.bare else { unreachable!() };
/// assert_eq!(b.decoded_len(), 5);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteSeq<'a> {
    raw: &'a [u8],
}

impl<'a> ByteSeq<'a> {
    /// The base64 text, padding included if it was sent.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let BareItem::ByteSeq(b) = sfv::parse_item(b":aGVsbG8=:")?.bare else { unreachable!() };
    /// assert_eq!(b.raw(), b"aGVsbG8=");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The exact length of the decoded bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let BareItem::ByteSeq(b) = sfv::parse_item(b":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:")?.bare else { unreachable!() };
    /// assert_eq!(b.decoded_len(), 31);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn decoded_len(&self) -> usize {
        let body = self.raw.iter().take_while(|&&b| b != b'=').count();
        body / 4 * 3 + (body % 4).saturating_sub(1)
    }
}

/// A Display String: the percent-encoded text between the quotes, validated
/// as UTF-8 during the parse.
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem};
///
/// let BareItem::DisplayString(d) = sfv::parse_item(b"%\"caf%c3%a9\"")?.bare else { unreachable!() };
/// assert_eq!(d.raw(), b"caf%c3%a9");
/// assert_eq!(d.decoded_len(), 5);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DisplayString<'a> {
    raw: &'a [u8],
}

impl<'a> DisplayString<'a> {
    /// The text as sent, `%xx` triples included.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let BareItem::DisplayString(d) = sfv::parse_item(b"%\"50%25\"")?.bare else { unreachable!() };
    /// assert_eq!(d.raw(), b"50%25");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// The length of the decoded UTF-8 text.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let BareItem::DisplayString(d) = sfv::parse_item(b"%\"caf%c3%a9\"")?.bare else { unreachable!() };
    /// assert_eq!(d.decoded_len(), 5);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn decoded_len(&self) -> usize {
        crate::pct::decoded_len(self.raw).unwrap_or(0)
    }

    /// Writes the decoded text into `out` and returns it.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::BufferTooSmall`]; nothing is written.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let BareItem::DisplayString(d) = sfv::parse_item(b"%\"caf%c3%a9\"")?.bare else { unreachable!() };
    /// let mut buf = [0u8; 8];
    /// assert_eq!(d.decode_into(&mut buf)?, "caf\u{e9}");
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn decode_into<'b>(&self, out: &'b mut [u8]) -> Result<&'b str> {
        crate::pct::decode_utf8_into(self.raw, out)
    }
}

/// Parameters of an item or an inner list. A repeated key keeps every
/// occurrence; [`get`](Self::get) takes the last, as RFC 9651 requires.
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem};
///
/// let params = sfv::parse_item(b"abc;a=1;b")?.params;
/// assert_eq!(params.len(), 2);
/// assert_eq!(params.get("a"), Some(BareItem::Integer(1)));
/// assert_eq!(params.get("b"), Some(BareItem::Boolean(true)));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SfParams<'a> {
    text: &'a [u8],
    count: usize,
}

impl<'a> SfParams<'a> {
    const EMPTY: Self = Self {
        text: &[],
        count: 0,
    };

    /// The parameters, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let params = sfv::parse_item(b"abc;a=1;b")?.params;
    /// let mut it = params.iter();
    /// assert_eq!(it.next(), Some(("a", BareItem::Integer(1))));
    /// assert_eq!(it.next(), Some(("b", BareItem::Boolean(true))));
    /// assert_eq!(it.next(), None);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> ParamIter<'a> {
        ParamIter {
            c: Cursor::new(self.text),
        }
    }

    /// The value of `key`: the last occurrence.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let params = sfv::parse_item(b"x;a=1;a=2")?.params;
    /// assert_eq!(params.get("a"), Some(BareItem::Integer(2)));
    /// assert_eq!(params.get("z"), None);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn get(&self, key: &str) -> Option<BareItem<'a>> {
        self.iter()
            .filter(|(k, _)| *k == key)
            .last()
            .map(|(_, v)| v)
    }

    /// The number of parameters, repeats included.
    ///
    /// # Examples
    ///
    /// ```
    /// let params = parse_net::sfv::parse_item(b"x;a=1;a=2")?.params;
    /// assert_eq!(params.len(), 2);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether there are no parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv;
    ///
    /// assert!(sfv::parse_item(b"x")?.params.is_empty());
    /// assert!(!sfv::parse_item(b"x;a")?.params.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The parameters of a validated [`SfParams`].
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem};
///
/// let params = sfv::parse_item(b"x;q=0.5")?.params;
/// let mut it = params.iter();
/// assert!(matches!(it.next(), Some(("q", BareItem::Decimal(d))) if d.thousandths() == 500));
/// assert!(it.next().is_none());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct ParamIter<'a> {
    c: Cursor<'a>,
}

impl<'a> Iterator for ParamIter<'a> {
    type Item = (&'a str, BareItem<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.c.peek() != Some(b';') {
            return None;
        }
        self.c.bump();
        self.c.skip_sp();
        let k = parse::key(&mut self.c, &RELAXED).ok()?;
        let v = if self.c.peek() == Some(b'=') {
            self.c.bump();
            parse::bare_item(&mut self.c, &RELAXED).ok()?
        } else {
            BareItem::Boolean(true)
        };
        Some((k, v))
    }
}

/// An item: a bare item and its parameters.
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem};
///
/// let item = sfv::parse_item(b"abc;v=2")?;
/// assert_eq!(item.bare, BareItem::Token("abc"));
/// assert_eq!(item.params.get("v"), Some(BareItem::Integer(2)));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Item<'a> {
    /// The bare item.
    pub bare: BareItem<'a>,
    /// Its parameters.
    pub params: SfParams<'a>,
}

/// An inner list: items in parentheses, and its own parameters.
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem, Member};
///
/// let list = sfv::parse_list(b"(a b);q=1")?;
/// let Some(Member::InnerList(inner)) = list.iter().next() else { unreachable!() };
/// assert_eq!(inner.len(), 2);
/// assert_eq!(inner.params().get("q"), Some(BareItem::Integer(1)));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct InnerList<'a> {
    text: &'a [u8],
    count: usize,
    params: SfParams<'a>,
}

impl<'a> InnerList<'a> {
    /// The items, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem, Member};
    ///
    /// let list = sfv::parse_list(b"(a b)")?;
    /// let Some(Member::InnerList(inner)) = list.iter().next() else { unreachable!() };
    /// assert!(inner.iter().map(|i| i.bare).eq([BareItem::Token("a"), BareItem::Token("b")]));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> InnerIter<'a> {
        let mut c = Cursor::new(self.text);
        c.bump(); // "("
        InnerIter { c }
    }

    /// The number of items.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, Member};
    ///
    /// let list = sfv::parse_list(b"(1 2 3)")?;
    /// let Some(Member::InnerList(inner)) = list.iter().next() else { unreachable!() };
    /// assert_eq!(inner.len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the inner list is empty (`()`).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, Member};
    ///
    /// let list = sfv::parse_list(b"()")?;
    /// let Some(Member::InnerList(inner)) = list.iter().next() else { unreachable!() };
    /// assert!(inner.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The inner list's own parameters.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem, Member};
    ///
    /// let list = sfv::parse_list(b"(a);lvl=5")?;
    /// let Some(Member::InnerList(inner)) = list.iter().next() else { unreachable!() };
    /// assert_eq!(inner.params().get("lvl"), Some(BareItem::Integer(5)));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn params(&self) -> SfParams<'a> {
        self.params
    }
}

/// The items of a validated [`InnerList`].
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem, Member};
///
/// let list = sfv::parse_list(b"(a;x b)")?;
/// let Some(Member::InnerList(inner)) = list.iter().next() else { unreachable!() };
/// let mut items = inner.iter();
/// assert_eq!(items.next().map(|i| i.params.len()), Some(1));
/// assert_eq!(items.next().map(|i| i.bare), Some(BareItem::Token("b")));
/// assert!(items.next().is_none());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct InnerIter<'a> {
    c: Cursor<'a>,
}

impl<'a> Iterator for InnerIter<'a> {
    type Item = Item<'a>;

    fn next(&mut self) -> Option<Item<'a>> {
        self.c.skip_sp();
        if matches!(self.c.peek(), Some(b')') | None) {
            return None;
        }
        item_view(&mut self.c)
    }
}

/// A list or dictionary member.
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem, Member};
///
/// let list = sfv::parse_list(b"a, (b c)")?;
/// let mut it = list.iter();
/// assert!(matches!(it.next(), Some(Member::Item(i)) if i.bare == BareItem::Token("a")));
/// assert!(matches!(it.next(), Some(Member::InnerList(l)) if l.len() == 2));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Member<'a> {
    /// An item.
    Item(Item<'a>),
    /// An inner list.
    InnerList(InnerList<'a>),
}

/// Parses an item at the cursor of validated text.
fn item_view<'a>(c: &mut Cursor<'a>) -> Option<Item<'a>> {
    let bare = parse::bare_item(c, &RELAXED).ok()?;
    let params = params_view(c)?;
    Some(Item { bare, params })
}

fn params_view<'a>(c: &mut Cursor<'a>) -> Option<SfParams<'a>> {
    let start = c.i;
    let count = parse::params(c, &RELAXED, |_, _| Ok(())).ok()?;
    Some(SfParams {
        text: c.s.get(start..c.i).unwrap_or(&[]),
        count,
    })
}

/// Parses a member at the cursor of validated text.
fn member_view<'a>(c: &mut Cursor<'a>) -> Option<Member<'a>> {
    if c.peek() != Some(b'(') {
        return item_view(c).map(Member::Item);
    }
    let start = c.i;
    let mut inner = *c;
    inner.bump(); // "("
    let mut count = 0usize;
    loop {
        inner.skip_sp();
        match inner.peek() {
            Some(b')') => {
                inner.bump();
                break;
            }
            None => return None,
            Some(_) => {}
        }
        let _ = item_view(&mut inner)?;
        count += 1;
    }
    let text = c.s.get(start..inner.i).unwrap_or(&[]);
    let params = params_view(&mut inner)?;
    *c = inner;
    Some(Member::InnerList(InnerList {
        text,
        count,
        params,
    }))
}

/// The value of a validated field line with its surrounding SP removed.
fn field_text(v: &[u8]) -> Cursor<'_> {
    let start = v.iter().take_while(|&&b| b == b' ').count();
    let end = v.len() - v.iter().rev().take_while(|&&b| b == b' ').count();
    Cursor::new(v.get(start..end.max(start)).unwrap_or(&[]))
}

/// Advances past the separator after a member of validated text; `false` at
/// the end.
fn next_member(c: &mut Cursor<'_>) -> bool {
    c.skip_ows();
    if c.peek() != Some(b',') {
        return false;
    }
    c.bump();
    c.skip_ows();
    true
}

/// A validated List.
///
/// # Examples
///
/// ```
/// let list = parse_net::sfv::parse_list(b"a, b;x, (c d)")?;
/// assert_eq!(list.len(), 3);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct List<'a> {
    text: &'a [u8],
    count: usize,
}

impl<'a> List<'a> {
    /// The members, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem, Member};
    ///
    /// let list = sfv::parse_list(b"a, 2")?;
    /// let mut it = list.iter();
    /// assert!(matches!(it.next(), Some(Member::Item(i)) if i.bare == BareItem::Token("a")));
    /// assert!(matches!(it.next(), Some(Member::Item(i)) if i.bare == BareItem::Integer(2)));
    /// assert!(it.next().is_none());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> ListIter<'a> {
        ListIter {
            c: Cursor::new(self.text),
            started: false,
        }
    }

    /// The number of members.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(parse_net::sfv::parse_list(b"a, b, c")?.len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the list is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(!parse_net::sfv::parse_list(b"a")?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The members of a validated [`List`].
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, Member};
///
/// let list = sfv::parse_list(b"a, (b c), d")?;
/// let inner = list.iter().filter(|m| matches!(m, Member::InnerList(_))).count();
/// assert_eq!(inner, 1);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct ListIter<'a> {
    c: Cursor<'a>,
    started: bool,
}

impl<'a> Iterator for ListIter<'a> {
    type Item = Member<'a>;

    fn next(&mut self) -> Option<Member<'a>> {
        if self.started && !next_member(&mut self.c) {
            return None;
        }
        self.started = true;
        if self.c.is_empty() {
            return None;
        }
        member_view(&mut self.c)
    }
}

/// A validated Dictionary. Every member is kept in order; a repeated key's
/// last value wins in [`get`](Self::get) and [`index_into`](Self::index_into).
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem, Member};
///
/// let d = sfv::parse_dictionary(b"a=1, b")?;
/// assert_eq!(d.len(), 2);
/// assert!(matches!(d.get("b"), Some(Member::Item(i)) if i.bare == BareItem::Boolean(true)));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Dictionary<'a> {
    text: &'a [u8],
    count: usize,
}

impl<'a> Dictionary<'a> {
    /// The members with their keys, in order (repeats included).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv;
    ///
    /// let d = sfv::parse_dictionary(b"a=1, b=2, a=3")?;
    /// assert!(d.iter().map(|(k, _)| k).eq(["a", "b", "a"]));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> DictIter<'a> {
        DictIter {
            c: Cursor::new(self.text),
            started: false,
        }
    }

    /// The member for `key`: the last occurrence.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem, Member};
    ///
    /// let d = sfv::parse_dictionary(b"a=1, b=(x y)")?;
    /// assert!(matches!(d.get("b"), Some(Member::InnerList(l)) if l.len() == 2));
    /// assert!(d.get("c").is_none());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Member<'a>> {
        self.iter()
            .filter(|(k, _)| *k == key)
            .last()
            .map(|(_, m)| m)
    }

    /// Fills `slots` with one entry per distinct key (the last value for a
    /// repeated key), in first-seen order, and returns the filled part: for
    /// callers that look up many keys.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::BufferTooSmall`] when there are more distinct keys than
    /// slots.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem, Item, Member};
    ///
    /// let d = sfv::parse_dictionary(b"a=1, b=2, a=3")?;
    /// let mut slots = [("", Member::Item(Item::new(BareItem::Boolean(false)))); 4];
    /// let index = d.index_into(&mut slots)?;
    /// assert_eq!(index.len(), 2);
    /// assert!(matches!(index[0], ("a", Member::Item(i)) if i.bare == BareItem::Integer(3)));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn index_into<'i>(
        &self,
        slots: &'i mut [(&'a str, Member<'a>)],
    ) -> Result<&'i [(&'a str, Member<'a>)]> {
        let mut n = 0usize;
        for (k, m) in self.iter() {
            let existing = slots
                .get_mut(..n)
                .and_then(|filled| filled.iter_mut().find(|(sk, _)| *sk == k));
            match existing {
                Some(slot) => slot.1 = m,
                None => {
                    let Some(slot) = slots.get_mut(n) else {
                        return err(ErrorKind::BufferTooSmall, 0);
                    };
                    *slot = (k, m);
                    n += 1;
                }
            }
        }
        Ok(slots.get(..n).unwrap_or(&[]))
    }

    /// The number of members, repeats included.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(parse_net::sfv::parse_dictionary(b"a=1, a=2")?.len(), 2);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the dictionary is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// assert!(!parse_net::sfv::parse_dictionary(b"a")?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// The members of a validated [`Dictionary`].
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem, Member};
///
/// let d = sfv::parse_dictionary(b"u=1, i")?;
/// let mut it = d.iter();
/// assert!(matches!(it.next(), Some(("u", Member::Item(i))) if i.bare == BareItem::Integer(1)));
/// assert!(matches!(it.next(), Some(("i", Member::Item(i))) if i.bare == BareItem::Boolean(true)));
/// assert!(it.next().is_none());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug)]
pub struct DictIter<'a> {
    c: Cursor<'a>,
    started: bool,
}

impl<'a> Iterator for DictIter<'a> {
    type Item = (&'a str, Member<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.started && !next_member(&mut self.c) {
            return None;
        }
        self.started = true;
        if self.c.is_empty() {
            return None;
        }
        let k = parse::key(&mut self.c, &RELAXED).ok()?;
        let m = if self.c.peek() == Some(b'=') {
            self.c.bump();
            member_view(&mut self.c)?
        } else {
            Member::Item(Item {
                bare: BareItem::Boolean(true),
                params: params_view(&mut self.c)?,
            })
        };
        Some((k, m))
    }
}

/// Several field lines read as one List.
///
/// # Examples
///
/// ```
/// let lines: [&[u8]; 2] = [b"a", b"b, c"];
/// let list = parse_net::sfv::parse_list_lines(&lines)?;
/// assert_eq!(list.len(), 3);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct ListLines<'a> {
    lines: &'a [&'a [u8]],
    count: usize,
}

impl<'a> ListLines<'a> {
    /// The members of every line, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem, Member};
    ///
    /// let lines: [&[u8]; 2] = [b"a", b"b"];
    /// let list = sfv::parse_list_lines(&lines)?;
    /// let mut it = list.iter();
    /// assert!(matches!(it.next(), Some(Member::Item(i)) if i.bare == BareItem::Token("a")));
    /// assert!(matches!(it.next(), Some(Member::Item(i)) if i.bare == BareItem::Token("b")));
    /// assert!(it.next().is_none());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = Member<'a>> + use<'a> {
        self.lines.iter().flat_map(|l| ListIter {
            c: field_text(l),
            started: false,
        })
    }

    /// The number of members across every line.
    ///
    /// # Examples
    ///
    /// ```
    /// let lines: [&[u8]; 3] = [b"a, b", b"c", b"d, e"];
    /// assert_eq!(parse_net::sfv::parse_list_lines(&lines)?.len(), 5);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether no line has a member.
    ///
    /// # Examples
    ///
    /// ```
    /// let lines: [&[u8]; 1] = [b"a"];
    /// assert!(!parse_net::sfv::parse_list_lines(&lines)?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Several field lines read as one Dictionary.
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem, Member};
///
/// let lines: [&[u8]; 2] = [b"a=1", b"b=2, a=3"];
/// let d = sfv::parse_dictionary_lines(&lines)?;
/// assert_eq!(d.len(), 3);
/// assert!(matches!(d.get("a"), Some(Member::Item(i)) if i.bare == BareItem::Integer(3)));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct DictionaryLines<'a> {
    lines: &'a [&'a [u8]],
    count: usize,
}

impl<'a> DictionaryLines<'a> {
    /// The members of every line, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// let lines: [&[u8]; 2] = [b"a=1", b"b=2, a=3"];
    /// let d = parse_net::sfv::parse_dictionary_lines(&lines)?;
    /// assert!(d.iter().map(|(k, _)| k).eq(["a", "b", "a"]));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, Member<'a>)> + use<'a> {
        self.lines.iter().flat_map(|l| DictIter {
            c: field_text(l),
            started: false,
        })
    }

    /// The member for `key`: the last occurrence across every line.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem, Member};
    ///
    /// let lines: [&[u8]; 2] = [b"a=1, b", b"a=2"];
    /// let d = sfv::parse_dictionary_lines(&lines)?;
    /// assert!(matches!(d.get("a"), Some(Member::Item(i)) if i.bare == BareItem::Integer(2)));
    /// assert!(d.get("c").is_none());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Member<'a>> {
        self.iter()
            .filter(|(k, _)| *k == key)
            .last()
            .map(|(_, m)| m)
    }

    /// The number of members across every line, repeats included.
    ///
    /// # Examples
    ///
    /// ```
    /// let lines: [&[u8]; 2] = [b"a=1, b", b"a=2"];
    /// assert_eq!(parse_net::sfv::parse_dictionary_lines(&lines)?.len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether no line has a member.
    ///
    /// # Examples
    ///
    /// ```
    /// let lines: [&[u8]; 1] = [b"a"];
    /// assert!(!parse_net::sfv::parse_dictionary_lines(&lines)?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// Receives a parse as events: the single-pass form, for callers that read
/// one key or count items without building a view.
///
/// # Examples
///
/// ```
/// use parse_net::{sfv::{BareItem, Parser, Visitor}, Limits, ParseError};
///
/// struct Urgency(Option<i64>, bool);
/// impl<'a> Visitor<'a> for Urgency {
///     fn item(&mut self, bare: BareItem<'a>) -> Result<(), ParseError> {
///         if let (true, BareItem::Integer(u)) = (self.1, bare) { self.0 = Some(u); }
///         Ok(())
///     }
///     fn param(&mut self, _: &'a str, _: BareItem<'a>) -> Result<(), ParseError> { Ok(()) }
///     fn key(&mut self, key: &'a str) -> Result<(), ParseError> { self.1 = key == "u"; Ok(()) }
/// }
///
/// let mut v = Urgency(None, false);
/// Parser::new(Limits::DEFAULT).visit_dictionary(b"u=5, i", &mut v)?;
/// assert_eq!(v.0, Some(5));
/// # Ok::<(), ParseError>(())
/// ```
pub trait Visitor<'a> {
    /// A bare item: a member, an inner-list item, or a dictionary value.
    ///
    /// # Errors
    ///
    /// Any error stops the parse and is returned.
    fn item(&mut self, bare: BareItem<'a>) -> Result<()>;

    /// A parameter of the most recent item or inner list.
    ///
    /// # Errors
    ///
    /// Any error stops the parse and is returned.
    fn param(&mut self, key: &'a str, value: BareItem<'a>) -> Result<()>;

    /// An inner list begins.
    ///
    /// # Errors
    ///
    /// Any error stops the parse and is returned.
    fn inner_list_start(&mut self) -> Result<()> {
        Ok(())
    }

    /// An inner list ends (its parameters follow).
    ///
    /// # Errors
    ///
    /// Any error stops the parse and is returned.
    fn inner_list_end(&mut self) -> Result<()> {
        Ok(())
    }

    /// A dictionary key; its value follows.
    ///
    /// # Errors
    ///
    /// Any error stops the parse and is returned.
    fn key(&mut self, key: &'a str) -> Result<()> {
        let _ = key;
        Ok(())
    }
}

struct VisitorEvents<'v, V>(&'v mut V);

impl<'a, V: Visitor<'a>> Events<'a> for VisitorEvents<'_, V> {
    fn item(&mut self, bare: BareItem<'a>) -> Result<()> {
        self.0.item(bare)
    }
    fn param(&mut self, key: &'a str, value: BareItem<'a>) -> Result<()> {
        self.0.param(key, value)
    }
    fn inner_start(&mut self) -> Result<()> {
        self.0.inner_list_start()
    }
    fn inner_end(&mut self) -> Result<()> {
        self.0.inner_list_end()
    }
    fn key(&mut self, key: &'a str) -> Result<()> {
        self.0.key(key)
    }
}

/// The configurable parser.
///
/// # Examples
///
/// ```
/// use parse_net::{sfv::Parser, ErrorKind, Limits};
///
/// let strict = Parser::new(Limits::DEFAULT.max_list_members(2));
/// assert_eq!(strict.list(b"a, b, c").unwrap_err().kind(), ErrorKind::TooManyMembers);
/// assert_eq!(Parser::default().list(b"a, b, c")?.len(), 3);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Parser {
    limits: Limits,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new(Limits::DEFAULT)
    }
}

impl Parser {
    /// A parser with `limits`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Parser, Limits};
    ///
    /// let p = Parser::new(Limits::DEFAULT.max_dictionary_members(1));
    /// assert!(p.dictionary(b"a").is_ok());
    /// assert!(p.dictionary(b"a, b").is_err());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn new(limits: Limits) -> Self {
        Self { limits }
    }

    /// Parses an Item (section 4.2.3).
    ///
    /// # Errors
    ///
    /// See [`parse_item`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{BareItem, Parser};
    ///
    /// let item = Parser::default().item(b"?0;x")?;
    /// assert_eq!(item.bare, BareItem::Boolean(false));
    /// assert_eq!(item.params.len(), 1);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn item<'a>(&self, v: &'a [u8]) -> Result<Item<'a>> {
        let l = self.limits;
        let ((bare, params), _, _) = parse::field(v, |c| {
            let bare = parse::bare_item(c, &l)?;
            let start = c.i;
            let count = parse::params(c, &l, |_, _| Ok(()))?;
            Ok((
                bare,
                SfParams {
                    text: c.s.get(start..c.i).unwrap_or(&[]),
                    count,
                },
            ))
        })?;
        Ok(Item { bare, params })
    }

    /// Parses a List (section 4.2.1).
    ///
    /// # Errors
    ///
    /// See [`parse_list`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::Parser;
    ///
    /// assert_eq!(Parser::default().list(b"a, (b c);q=1")?.len(), 2);
    /// assert!(Parser::default().list(b"a,,b").is_err());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn list<'a>(&self, v: &'a [u8]) -> Result<List<'a>> {
        let l = self.limits;
        let (count, start, end) = parse::field(v, |c| parse::list(c, &l, &mut Nothing))?;
        Ok(List {
            text: v.get(start..end).unwrap_or(&[]),
            count,
        })
    }

    /// Parses a Dictionary (section 4.2.2).
    ///
    /// # Errors
    ///
    /// See [`parse_dictionary`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{BareItem, Member, Parser};
    ///
    /// let d = Parser::default().dictionary(b"a=1, b")?;
    /// assert!(matches!(d.get("a"), Some(Member::Item(i)) if i.bare == BareItem::Integer(1)));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn dictionary<'a>(&self, v: &'a [u8]) -> Result<Dictionary<'a>> {
        let l = self.limits;
        let (count, start, end) = parse::field(v, |c| parse::dictionary(c, &l, &mut Nothing))?;
        Ok(Dictionary {
            text: v.get(start..end).unwrap_or(&[]),
            count,
        })
    }

    /// Parses several field lines as one List: each line must parse on its
    /// own, an empty line fails the field, and the member limit counts
    /// across lines.
    ///
    /// # Errors
    ///
    /// As [`list`](Self::list), with [`ParseError::line`] set; an empty line
    /// is [`ErrorKind::Empty`].
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::Parser, ErrorKind};
    ///
    /// let good: [&[u8]; 2] = [b"a", b"b, c"];
    /// assert_eq!(Parser::default().list_lines(&good)?.len(), 3);
    /// let bad: [&[u8]; 2] = [b"a", b""];
    /// let e = Parser::default().list_lines(&bad).unwrap_err();
    /// assert_eq!((e.kind(), e.line()), (ErrorKind::Empty, 1));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn list_lines<'a>(&self, lines: &'a [&'a [u8]]) -> Result<ListLines<'a>> {
        let mut count = 0usize;
        for (n, line) in lines.iter().enumerate() {
            if line.iter().all(|&b| b == b' ') {
                return Err(ParseError::new(ErrorKind::Empty, 0).on_line(n));
            }
            count += self.list(line).map_err(|e| e.on_line(n))?.len();
            if count > usize::from(self.limits.list_members) {
                return Err(ParseError::new(ErrorKind::TooManyMembers, 0).on_line(n));
            }
        }
        Ok(ListLines { lines, count })
    }

    /// Parses several field lines as one Dictionary (the last value of a
    /// repeated key wins across lines).
    ///
    /// # Errors
    ///
    /// As [`list_lines`](Self::list_lines).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{BareItem, Member, Parser};
    ///
    /// let lines: [&[u8]; 2] = [b"a=1", b"a=2"];
    /// let d = Parser::default().dictionary_lines(&lines)?;
    /// assert!(matches!(d.get("a"), Some(Member::Item(i)) if i.bare == BareItem::Integer(2)));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn dictionary_lines<'a>(&self, lines: &'a [&'a [u8]]) -> Result<DictionaryLines<'a>> {
        let mut count = 0usize;
        for (n, line) in lines.iter().enumerate() {
            if line.iter().all(|&b| b == b' ') {
                return Err(ParseError::new(ErrorKind::Empty, 0).on_line(n));
            }
            count += self.dictionary(line).map_err(|e| e.on_line(n))?.len();
            if count > usize::from(self.limits.dictionary_members) {
                return Err(ParseError::new(ErrorKind::TooManyMembers, 0).on_line(n));
            }
        }
        Ok(DictionaryLines { lines, count })
    }

    /// Parses an Item, reporting it to `visitor`.
    ///
    /// # Errors
    ///
    /// As [`item`](Self::item), or the visitor's error.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::{BareItem, Parser, Visitor}, Limits, ParseError};
    ///
    /// struct Count(usize);
    /// impl<'a> Visitor<'a> for Count {
    ///     fn item(&mut self, _: BareItem<'a>) -> Result<(), ParseError> { Ok(()) }
    ///     fn param(&mut self, _: &'a str, _: BareItem<'a>) -> Result<(), ParseError> { self.0 += 1; Ok(()) }
    /// }
    ///
    /// let mut c = Count(0);
    /// Parser::new(Limits::DEFAULT).visit_item(b"a;x=1;y", &mut c)?;
    /// assert_eq!(c.0, 2);
    /// # Ok::<(), ParseError>(())
    /// ```
    pub fn visit_item<'a, V: Visitor<'a>>(&self, v: &'a [u8], visitor: &mut V) -> Result<()> {
        let l = self.limits;
        parse::field(v, |c| {
            let mut ev = VisitorEvents(visitor);
            let bare = parse::bare_item(c, &l)?;
            ev.item(bare)?;
            parse::params(c, &l, |k, x| ev.param(k, x)).map(|_| ())
        })
        .map(|_| ())
    }

    /// Parses a List, reporting it to `visitor`.
    ///
    /// # Errors
    ///
    /// As [`list`](Self::list), or the visitor's error.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::{BareItem, Parser, Visitor}, Limits, ParseError};
    ///
    /// struct Count(usize);
    /// impl<'a> Visitor<'a> for Count {
    ///     fn item(&mut self, _: BareItem<'a>) -> Result<(), ParseError> { self.0 += 1; Ok(()) }
    ///     fn param(&mut self, _: &'a str, _: BareItem<'a>) -> Result<(), ParseError> { Ok(()) }
    /// }
    ///
    /// let mut c = Count(0);
    /// Parser::new(Limits::DEFAULT).visit_list(b"a, (b c);q", &mut c)?;
    /// assert_eq!(c.0, 3);
    /// # Ok::<(), ParseError>(())
    /// ```
    pub fn visit_list<'a, V: Visitor<'a>>(&self, v: &'a [u8], visitor: &mut V) -> Result<()> {
        let l = self.limits;
        parse::field(v, |c| parse::list(c, &l, &mut VisitorEvents(visitor))).map(|_| ())
    }

    /// Parses a Dictionary, reporting it to `visitor`.
    ///
    /// # Errors
    ///
    /// As [`dictionary`](Self::dictionary), or the visitor's error.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{sfv::{BareItem, Parser, Visitor}, Limits, ParseError};
    ///
    /// struct Count(usize);
    /// impl<'a> Visitor<'a> for Count {
    ///     fn item(&mut self, _: BareItem<'a>) -> Result<(), ParseError> { Ok(()) }
    ///     fn param(&mut self, _: &'a str, _: BareItem<'a>) -> Result<(), ParseError> { Ok(()) }
    ///     fn key(&mut self, _: &'a str) -> Result<(), ParseError> { self.0 += 1; Ok(()) }
    /// }
    ///
    /// let mut c = Count(0);
    /// Parser::new(Limits::DEFAULT).visit_dictionary(b"a=1, b, c=(x y)", &mut c)?;
    /// assert_eq!(c.0, 3);
    /// # Ok::<(), ParseError>(())
    /// ```
    pub fn visit_dictionary<'a, V: Visitor<'a>>(&self, v: &'a [u8], visitor: &mut V) -> Result<()> {
        let l = self.limits;
        parse::field(v, |c| parse::dictionary(c, &l, &mut VisitorEvents(visitor))).map(|_| ())
    }
}

/// Parses an Item with the default [`Limits`] (RFC 9651 section 4.2.3).
///
/// # Errors
///
/// [`ErrorKind::TrailingData`]; for the bare item:
/// [`ErrorKind::InvalidNumber`] (`-` alone, `1.`, a Decimal after `@`),
/// [`ErrorKind::NumberOverflow`] (16 digits, 13 integer digits in a Decimal,
/// 4 fractional digits), [`ErrorKind::InvalidByte`],
/// [`ErrorKind::InvalidQuotedPair`], [`ErrorKind::UnterminatedQuote`],
/// [`ErrorKind::InvalidBase64`], [`ErrorKind::InvalidPercentEncoding`]
/// (uppercase hex in a Display String), [`ErrorKind::InvalidUtf8`],
/// [`ErrorKind::OutOfRange`] (a Date outside years 1 to 9999),
/// [`ErrorKind::TooLong`]; for parameters: [`ErrorKind::InvalidKey`],
/// [`ErrorKind::TooManyMembers`].
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem};
///
/// assert_eq!(sfv::parse_item(b"?1")?.bare, BareItem::Boolean(true));
/// assert_eq!(sfv::parse_item(b"@1659578233")?.bare, BareItem::Date(1_659_578_233));
/// assert!(sfv::parse_item(b"%\"%C3%A9\"").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_item(value: &[u8]) -> Result<Item<'_>> {
    Parser::default().item(value)
}

/// Parses a List with the default [`Limits`] (RFC 9651 section 4.2.1).
///
/// # Errors
///
/// As [`parse_item`], and [`ErrorKind::TrailingSeparator`] (`a, b,`),
/// [`ErrorKind::ExpectedSeparator`], [`ErrorKind::TooManyMembers`].
///
/// # Examples
///
/// ```
/// assert_eq!(parse_net::sfv::parse_list(b"a, b,").unwrap_err().kind(), parse_net::ErrorKind::TrailingSeparator);
/// ```
pub fn parse_list(value: &[u8]) -> Result<List<'_>> {
    Parser::default().list(value)
}

/// Parses a Dictionary with the default [`Limits`] (RFC 9651 section 4.2.2).
///
/// # Errors
///
/// As [`parse_list`], and [`ErrorKind::InvalidKey`].
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem, Member};
///
/// let d = sfv::parse_dictionary(b"a=1, a=2")?;
/// assert!(matches!(d.get("a"), Some(Member::Item(i)) if i.bare == BareItem::Integer(2)));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_dictionary(value: &[u8]) -> Result<Dictionary<'_>> {
    Parser::default().dictionary(value)
}

/// Parses several field lines as one List with the default [`Limits`].
///
/// # Errors
///
/// As [`Parser::list_lines`].
///
/// # Examples
///
/// ```
/// let lines: [&[u8]; 2] = [b"a, b", b"c"];
/// assert_eq!(parse_net::sfv::parse_list_lines(&lines)?.len(), 3);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_list_lines<'a>(lines: &'a [&'a [u8]]) -> Result<ListLines<'a>> {
    Parser::default().list_lines(lines)
}

/// Parses several field lines as one Dictionary with the default [`Limits`].
///
/// # Errors
///
/// As [`Parser::dictionary_lines`].
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, BareItem, Member};
///
/// let lines: [&[u8]; 2] = [b"u=1", b"i"];
/// let d = sfv::parse_dictionary_lines(&lines)?;
/// assert_eq!(d.len(), 2);
/// assert!(matches!(d.get("i"), Some(Member::Item(i)) if i.bare == BareItem::Boolean(true)));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_dictionary_lines<'a>(lines: &'a [&'a [u8]]) -> Result<DictionaryLines<'a>> {
    Parser::default().dictionary_lines(lines)
}

impl<'a> Item<'a> {
    /// An item with no parameters (for filling the slots of
    /// [`Dictionary::index_into`]).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{BareItem, Item};
    ///
    /// let item = Item::new(BareItem::Integer(7));
    /// assert_eq!(item.bare, BareItem::Integer(7));
    /// assert!(item.params.is_empty());
    /// ```
    #[must_use]
    pub const fn new(bare: BareItem<'a>) -> Self {
        Self {
            bare,
            params: SfParams::EMPTY,
        }
    }
}

#[cfg(test)]
mod tests;
