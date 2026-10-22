//! Owned Structured Field values (`alloc`): one buffer per value, the same
//! view back.
//!
//! # Examples
//!
//! ```
//! use parse_net::sfv::{self, owned::OwnedDictionary, BareItem, Member};
//!
//! let owned: OwnedDictionary = {
//!     let input = b"u=1, i".to_vec();
//!     sfv::parse_dictionary(&input)?.to_owned()
//! };
//! assert!(matches!(owned.as_view().get("u"), Some(Member::Item(i)) if i.bare == BareItem::Integer(1)));
//! # Ok::<(), parse_net::ParseError>(())
//! ```

use alloc::vec::Vec;

use super::{
    BareItem, ByteSeq, Decimal, Dictionary, DisplayString, Item, List, SfParams, SfString,
};

/// The scalar part of a bare item; text kinds keep their bytes in a buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Kind {
    Integer(i64),
    Decimal(Decimal),
    String { escapes: bool },
    Token,
    ByteSeq,
    Boolean(bool),
    Date(i64),
    DisplayString,
}

fn split<'a>(b: &BareItem<'a>) -> (Kind, &'a [u8]) {
    match *b {
        BareItem::Integer(i) => (Kind::Integer(i), &[]),
        BareItem::Decimal(d) => (Kind::Decimal(d), &[]),
        BareItem::String(s) => (Kind::String { escapes: s.escapes }, s.raw.as_bytes()),
        BareItem::Token(t) => (Kind::Token, t.as_bytes()),
        BareItem::ByteSeq(s) => (Kind::ByteSeq, s.raw),
        BareItem::Boolean(v) => (Kind::Boolean(v), &[]),
        BareItem::Date(d) => (Kind::Date(d), &[]),
        BareItem::DisplayString(s) => (Kind::DisplayString, s.raw),
    }
}

fn view(kind: Kind, bytes: &[u8]) -> BareItem<'_> {
    // Text kinds hold ASCII copied from a validated view.
    let text = core::str::from_utf8(bytes).unwrap_or("");
    match kind {
        Kind::Integer(i) => BareItem::Integer(i),
        Kind::Decimal(d) => BareItem::Decimal(d),
        Kind::String { escapes } => BareItem::String(SfString { raw: text, escapes }),
        Kind::Token => BareItem::Token(text),
        Kind::ByteSeq => BareItem::ByteSeq(ByteSeq { raw: bytes }),
        Kind::Boolean(v) => BareItem::Boolean(v),
        Kind::Date(d) => BareItem::Date(d),
        Kind::DisplayString => BareItem::DisplayString(DisplayString { raw: bytes }),
    }
}

/// An owned [`BareItem`].
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, owned::OwnedBareItem, BareItem};
///
/// let owned: OwnedBareItem = {
///     let input = b"tok".to_vec();
///     sfv::parse_item(&input)?.bare.to_owned()
/// };
/// assert_eq!(owned.as_view(), BareItem::Token("tok"));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnedBareItem {
    kind: Kind,
    buf: Vec<u8>,
}

impl BareItem<'_> {
    /// Copies the bare item (one allocation for a text kind, none otherwise).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let bare = sfv::parse_item(b"\"hi\"")?.bare;
    /// assert_eq!(bare.to_owned().as_view(), bare);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn to_owned(&self) -> OwnedBareItem {
        let (kind, bytes) = split(self);
        OwnedBareItem {
            kind,
            buf: bytes.to_vec(),
        }
    }
}

impl OwnedBareItem {
    /// The view over the owned bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let owned = BareItem::Integer(9).to_owned();
    /// assert_eq!(owned.as_view(), BareItem::Integer(9));
    /// ```
    #[must_use]
    pub fn as_view(&self) -> BareItem<'_> {
        view(self.kind, &self.buf)
    }
}

/// An owned [`Item`]: the bare item's bytes and the parameter text in one
/// buffer.
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, owned::OwnedItem, BareItem};
///
/// let owned: OwnedItem = {
///     let input = b"tok;v=2".to_vec();
///     sfv::parse_item(&input)?.to_owned()
/// };
/// assert_eq!(owned.as_view().params.get("v"), Some(BareItem::Integer(2)));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnedItem {
    kind: Kind,
    buf: Vec<u8>,
    split: usize,
    count: usize,
}

impl Item<'_> {
    /// Copies the item (one allocation).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv;
    ///
    /// let item = sfv::parse_item(b"a;x=1")?;
    /// assert_eq!(item.to_owned().as_view(), item);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn to_owned(&self) -> OwnedItem {
        let (kind, bytes) = split(&self.bare);
        let mut buf = Vec::with_capacity(bytes.len() + self.params.text.len());
        buf.extend_from_slice(bytes);
        buf.extend_from_slice(self.params.text);
        OwnedItem {
            kind,
            buf,
            split: bytes.len(),
            count: self.params.count,
        }
    }
}

impl OwnedItem {
    /// The view over the owned bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem};
    ///
    /// let owned = sfv::parse_item(b"5;unit=s")?.to_owned();
    /// let view = owned.as_view();
    /// assert_eq!(view.bare, BareItem::Integer(5));
    /// assert_eq!(view.params.get("unit"), Some(BareItem::Token("s")));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn as_view(&self) -> Item<'_> {
        let (bare, text) = self.buf.split_at(self.split.min(self.buf.len()));
        Item {
            bare: view(self.kind, bare),
            params: SfParams {
                text,
                count: self.count,
            },
        }
    }
}

/// An owned [`List`].
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, owned::OwnedList};
///
/// let owned: OwnedList = {
///     let input = b"a, (b c)".to_vec();
///     sfv::parse_list(&input)?.to_owned()
/// };
/// assert_eq!(owned.as_view().len(), 2);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnedList {
    text: Vec<u8>,
    count: usize,
}

impl List<'_> {
    /// Copies the list (one allocation).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv;
    ///
    /// let list = sfv::parse_list(b"a, b")?;
    /// assert_eq!(list.to_owned().as_view(), list);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn to_owned(&self) -> OwnedList {
        OwnedList {
            text: self.text.to_vec(),
            count: self.count,
        }
    }
}

impl OwnedList {
    /// The view over the owned bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem, Member};
    ///
    /// let owned = sfv::parse_list(b"1, 2")?.to_owned();
    /// assert!(matches!(owned.as_view().iter().next(), Some(Member::Item(i)) if i.bare == BareItem::Integer(1)));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn as_view(&self) -> List<'_> {
        List {
            text: &self.text,
            count: self.count,
        }
    }
}

/// An owned [`Dictionary`].
///
/// # Examples
///
/// ```
/// use parse_net::sfv::{self, owned::OwnedDictionary};
///
/// let owned: OwnedDictionary = {
///     let input = b"a=1, b".to_vec();
///     sfv::parse_dictionary(&input)?.to_owned()
/// };
/// assert_eq!(owned.as_view().len(), 2);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OwnedDictionary {
    text: Vec<u8>,
    count: usize,
}

impl Dictionary<'_> {
    /// Copies the dictionary (one allocation).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv;
    ///
    /// let d = sfv::parse_dictionary(b"a=1, b")?;
    /// assert_eq!(d.to_owned().as_view(), d);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn to_owned(&self) -> OwnedDictionary {
        OwnedDictionary {
            text: self.text.to_vec(),
            count: self.count,
        }
    }
}

impl OwnedDictionary {
    /// The view over the owned bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::sfv::{self, BareItem, Member};
    ///
    /// let owned = sfv::parse_dictionary(b"q=0.5")?.to_owned();
    /// assert!(matches!(owned.as_view().get("q"), Some(Member::Item(i)) if i.bare == BareItem::Decimal(sfv::Decimal::from_thousandths(500)?)));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub fn as_view(&self) -> Dictionary<'_> {
        Dictionary {
            text: &self.text,
            count: self.count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{parse_dictionary, parse_item, parse_list};

    #[test]
    fn test_owned_sfv_gives_the_same_view() {
        for v in [
            &b"1;a=2"[..],
            b"\"a\\\"b\";x",
            b":YQ==:",
            b"%\"%c3%a9\"",
            b"?0",
            b"@1",
            b"tok;p=1.5",
            b"-0.5",
        ] {
            let i = parse_item(v).unwrap();
            assert_eq!(i.to_owned().as_view(), i);
            assert_eq!(i.bare.to_owned().as_view(), i.bare);
        }
        let l = parse_list(b"a, (b c);d, \"e\"").unwrap();
        assert_eq!(l.to_owned().as_view(), l);
        let d = parse_dictionary(b"a=1, b, c=(x y);q").unwrap();
        assert_eq!(d.to_owned().as_view(), d);
    }
}
