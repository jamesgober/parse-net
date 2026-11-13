//! Content negotiation: quality values and the selection of the best offer
//! for `Accept`, `Accept-Language`, `Accept-Encoding`, and `Accept-Charset`
//! (RFC 9110 section 12, RFC 4647).
//!
//! Every selection walks the request's members against the server's offers
//! with no allocation: offers are taken 32 at a time, and the members are
//! read once per group of 32 (work is members times offers, with members
//! bounded by [`Limits::max_list_members`]).
//!
//! # Examples
//!
//! ```
//! use parse_net as pn;
//!
//! let chrome = b"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
//! assert_eq!(pn::best_media(Some(chrome), &["application/json", "text/html"]), Some(1));
//! assert_eq!(pn::best_language(Some(b"en-US, fr;q=0.8"), &["fr", "en"]), Some(1));
//! assert_eq!(pn::best_encoding(Some(b"gzip, br;q=0.9"), &["br", "gzip"]), Some(1));
//! ```

use crate::{
    error::{ErrorKind, ParseError, Result, err},
    limits::Limits,
    list,
    media::{self, MediaType},
    param::{self, Params},
    text::{self, Word},
};

/// A quality value: 0 to 1 in thousandths (RFC 9110 section 12.4.2). No
/// floating point.
///
/// # Examples
///
/// ```
/// use parse_net::QValue;
///
/// assert_eq!(QValue::parse(b"0.5")?.thousandths(), 500);
/// assert_eq!(QValue::parse(b"1.000")?, QValue::ONE);
/// assert!(QValue::parse(b"1.5").is_err() && QValue::parse(b".5").is_err());
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QValue(u16);

impl QValue {
    /// `q=1`, the weight of a member without `q`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::QValue;
    ///
    /// assert_eq!(QValue::ONE.thousandths(), 1000);
    /// assert_eq!(QValue::parse(b"1")?, QValue::ONE);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub const ONE: Self = Self(1000);
    /// `q=0`: not acceptable.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::QValue;
    ///
    /// assert_eq!(QValue::parse(b"0.000")?, QValue::ZERO);
    /// assert!(QValue::ZERO < QValue::ONE);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub const ZERO: Self = Self(0);

    /// The weight `t` thousandths, if `t` is at most 1000.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::QValue;
    ///
    /// assert_eq!(QValue::from_thousandths(500), Some(QValue::parse(b"0.5")?));
    /// assert_eq!(QValue::from_thousandths(1001), None);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn from_thousandths(t: u16) -> Option<Self> {
        if t <= 1000 { Some(Self(t)) } else { None }
    }

    /// The weight in thousandths, 0 to 1000.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(parse_net::QValue::parse(b"0.05")?.thousandths(), 50);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn thousandths(self) -> u16 {
        self.0
    }

    /// Parses `( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )`.
    ///
    /// # Errors
    ///
    /// [`ErrorKind::InvalidQValue`] for anything else (`1.5`, `0.1234`, `.5`,
    /// `-1`, `1.001`, an empty value).
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::QValue;
    ///
    /// assert_eq!(QValue::parse(b"0.125")?.thousandths(), 125);
    /// assert!(QValue::parse(b"0.1234").is_err());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn parse(s: &[u8]) -> Result<Self> {
        let (first, rest) = match s.split_first() {
            Some((&f, r)) => (f, r),
            None => return err(ErrorKind::InvalidQValue, 0),
        };
        let frac = match rest.split_first() {
            None => &[][..],
            Some((b'.', digits)) if digits.len() <= 3 => digits,
            Some(_) => return err(ErrorKind::InvalidQValue, 1),
        };
        if let Some(i) = frac.iter().position(|b| !b.is_ascii_digit()) {
            return err(ErrorKind::InvalidQValue, 2 + i);
        }
        let mut thousandths = 0u16;
        let mut scale = 100u16;
        for &d in frac {
            thousandths += u16::from(d - b'0') * scale;
            scale /= 10;
        }
        match first {
            b'0' => Ok(Self(thousandths)),
            b'1' if thousandths == 0 => Ok(Self::ONE),
            // The first byte that puts the value above 1.
            b'1' => err(
                ErrorKind::InvalidQValue,
                2 + frac.iter().position(|&d| d != b'0').unwrap_or(0),
            ),
            _ => err(ErrorKind::InvalidQValue, 0),
        }
    }
}

/// How `Accept-Language` ranges are matched against offered tags.
///
/// # Examples
///
/// ```
/// use parse_net::negotiate::{LanguageMatching, Negotiator};
///
/// let offers = ["en-US"];
/// assert_eq!(Negotiator::new().language(Some(b"en"), &offers).index(), None);
/// let filter = Negotiator::new().language_matching(LanguageMatching::BasicFilter);
/// assert_eq!(filter.language(Some(b"en"), &offers).index(), Some(0));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum LanguageMatching {
    /// RFC 4647 section 3.4 lookup: a range matches an offer equal to it or
    /// reached by removing subtags from its end (`en-US` matches `en`).
    #[default]
    Lookup,
    /// RFC 4647 section 3.3.1 basic filtering: a range matches an offer equal
    /// to it or starting with it and `-` (`en` matches `en-US`).
    BasicFilter,
}

/// What a selection does with a header that does not parse.
///
/// # Examples
///
/// ```
/// use parse_net::negotiate::{MalformedPolicy, Negotiator, Outcome};
///
/// let bad = Some(&b"text/html;q=x"[..]);
/// assert_eq!(Negotiator::new().media(bad, &["text/html"]), Outcome::HeaderIgnored { index: 0 });
/// let strict = Negotiator::new().on_malformed(MalformedPolicy::Refuse);
/// assert!(matches!(strict.media(bad, &["text/html"]), Outcome::Refused(_)));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum MalformedPolicy {
    /// Treat the header as absent (RFC 9110 lets a server ignore it) and say
    /// so with [`Outcome::HeaderIgnored`].
    #[default]
    TreatAsAbsent,
    /// Report [`Outcome::Refused`], so the caller can answer 400.
    Refuse,
}

/// The result of a selection.
///
/// # Examples
///
/// ```
/// use parse_net::{negotiate::{Negotiator, Outcome}, QValue};
///
/// let n = Negotiator::new();
/// assert_eq!(n.media(Some(b"text/html"), &["text/html"]), Outcome::Chosen { index: 0, weight: QValue::ONE });
/// assert_eq!(n.media(Some(b"image/png"), &["text/html"]), Outcome::NoneAcceptable);
/// assert_eq!(n.media(Some(b"text/html;q=9"), &["text/html"]).index(), Some(0));
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The offer at `index` is the best, with this weight.
    Chosen {
        /// The index into the offers.
        index: usize,
        /// Its weight.
        weight: QValue,
    },
    /// No offer is acceptable: answer 406, or send a default.
    NoneAcceptable,
    /// The header did not parse and was treated as absent; the offer at
    /// `index` (the first) is chosen.
    HeaderIgnored {
        /// The index into the offers.
        index: usize,
    },
    /// The header did not parse, and the policy is to refuse it.
    Refused(ParseError),
}

impl Outcome {
    /// The chosen offer, if any.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::negotiate::Negotiator;
    ///
    /// let n = Negotiator::new();
    /// assert_eq!(n.encoding(Some(b"gzip"), &["br", "gzip"]).index(), Some(1));
    /// assert_eq!(n.encoding(Some(b"gzip"), &["br"]).index(), None);
    /// ```
    #[must_use]
    pub const fn index(&self) -> Option<usize> {
        match self {
            Self::Chosen { index, .. } | Self::HeaderIgnored { index } => Some(*index),
            _ => None,
        }
    }
}

/// The configurable form of the `best_*` functions.
///
/// # Examples
///
/// ```
/// use parse_net::negotiate::{LanguageMatching, MalformedPolicy, Negotiator, Outcome};
///
/// let n = Negotiator::new().language_matching(LanguageMatching::BasicFilter);
/// assert_eq!(n.language(Some(b"en"), &["fr", "en-GB"]).index(), Some(1));
/// let strict = Negotiator::new().on_malformed(MalformedPolicy::Refuse);
/// assert!(matches!(strict.media(Some(b"text/html;q=2"), &["text/html"]), Outcome::Refused(_)));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Negotiator {
    limits: Limits,
    language: LanguageMatching,
    malformed: MalformedPolicy,
}

impl Default for Negotiator {
    fn default() -> Self {
        Self::new()
    }
}

/// How many offers are evaluated per pass over the members.
const GROUP: usize = 32;

/// The weight and specificity of the best member seen for one offer.
#[derive(Clone, Copy, Default)]
struct Best {
    specificity: u16,
    weight: u16,
    seen: bool,
}

impl Best {
    /// Takes `weight` when `specificity` beats what is held, or equals it
    /// for the first time (the earlier member wins a tie).
    fn offer(&mut self, specificity: u16, weight: QValue) {
        if !self.seen || specificity > self.specificity {
            *self = Self {
                specificity,
                weight: weight.0,
                seen: true,
            };
        }
    }
}

/// The highest weight, ties going to the earlier offer.
fn pick(weights: impl Iterator<Item = (usize, Option<u16>)>) -> Outcome {
    let mut best: Option<(usize, u16)> = None;
    for (index, w) in weights {
        if let Some(w) = w {
            if w > 0 && best.is_none_or(|(_, b)| w > b) {
                best = Some((index, w));
            }
        }
    }
    match best {
        Some((index, w)) => Outcome::Chosen {
            index,
            weight: QValue(w),
        },
        None => Outcome::NoneAcceptable,
    }
}

impl Negotiator {
    /// Default limits, RFC 4647 lookup, malformed headers treated as absent.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::negotiate::Negotiator;
    ///
    /// let n = Negotiator::new();
    /// assert_eq!(n, Negotiator::default());
    /// assert_eq!(n.media(None, &["text/html", "text/plain"]).index(), Some(0));
    /// ```
    #[must_use]
    pub const fn new() -> Self {
        Self {
            limits: Limits::DEFAULT,
            language: LanguageMatching::Lookup,
            malformed: MalformedPolicy::TreatAsAbsent,
        }
    }

    /// Sets the limits the request headers are parsed with.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{negotiate::{Negotiator, Outcome}, Limits};
    ///
    /// let n = Negotiator::new().limits(Limits::DEFAULT.max_list_members(1));
    /// assert_eq!(n.media(Some(b"text/plain, text/html"), &["text/html"]), Outcome::HeaderIgnored { index: 0 });
    /// ```
    #[must_use]
    pub const fn limits(self, l: Limits) -> Self {
        Self { limits: l, ..self }
    }

    /// Sets how language ranges are matched.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::negotiate::{LanguageMatching, Negotiator};
    ///
    /// let n = Negotiator::new().language_matching(LanguageMatching::BasicFilter);
    /// assert_eq!(n.language(Some(b"de"), &["fr", "de-AT"]).index(), Some(1));
    /// ```
    #[must_use]
    pub const fn language_matching(self, m: LanguageMatching) -> Self {
        Self {
            language: m,
            ..self
        }
    }

    /// Sets what happens with a header that does not parse.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{negotiate::{MalformedPolicy, Negotiator, Outcome}, ErrorKind};
    ///
    /// let n = Negotiator::new().on_malformed(MalformedPolicy::Refuse);
    /// let out = n.encoding(Some(b"gzip;q=2"), &["gzip"]);
    /// assert!(matches!(out, Outcome::Refused(e) if e.kind() == ErrorKind::InvalidQValue));
    /// ```
    #[must_use]
    pub const fn on_malformed(self, p: MalformedPolicy) -> Self {
        Self {
            malformed: p,
            ..self
        }
    }

    /// The outcome for a malformed header; `fallback` is the offer an absent
    /// header would choose.
    fn malformed(&self, e: ParseError, fallback: Option<usize>) -> Outcome {
        match (self.malformed, fallback) {
            (MalformedPolicy::Refuse, _) => Outcome::Refused(e),
            (MalformedPolicy::TreatAsAbsent, None) => Outcome::NoneAcceptable,
            (MalformedPolicy::TreatAsAbsent, Some(index)) => Outcome::HeaderIgnored { index },
        }
    }

    /// Selects the best of `offers` (media types such as `"text/html"`) for
    /// `Accept`.
    ///
    /// An offer's weight is the `q` of the most specific matching range
    /// (RFC 9110 section 12.5.1); `q=0` means not acceptable; ties go to the
    /// earlier offer. An absent header makes every offer acceptable, so the
    /// first wins. An offer that is not a valid media type is never chosen.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{negotiate::{Negotiator, Outcome}, QValue};
    ///
    /// let n = Negotiator::new();
    /// let accept = Some(&b"text/*;q=0.5, text/html"[..]);
    /// assert_eq!(n.media(accept, &["text/plain", "text/html"]), Outcome::Chosen { index: 1, weight: QValue::ONE });
    /// assert_eq!(n.media(accept, &["image/png"]), Outcome::NoneAcceptable);
    /// ```
    #[must_use]
    pub fn media(&self, accept: Option<&[u8]>, offers: &[&str]) -> Outcome {
        match (accept, first_media(offers)) {
            (None, Some(index)) => Outcome::Chosen {
                index,
                weight: QValue::ONE,
            },
            (None, None) => Outcome::NoneAcceptable,
            (Some(v), _) => self.media_lines([v], offers),
        }
    }

    /// As [`media`](Self::media), for several `Accept` field lines read as
    /// one list.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::negotiate::Negotiator;
    ///
    /// let lines: [&[u8]; 2] = [b"text/plain;q=0.5", b"application/json"];
    /// assert_eq!(Negotiator::new().media_lines(lines, &["text/plain", "application/json"]).index(), Some(1));
    /// ```
    #[must_use]
    pub fn media_lines<'a, I>(&self, lines: I, offers: &[&str]) -> Outcome
    where
        I: IntoIterator<Item = &'a [u8]>,
        I::IntoIter: Clone,
    {
        let lines = lines.into_iter();
        let members = match list::parse_lines(lines.clone(), &self.limits) {
            Ok(l) => l,
            Err(e) => return self.malformed(e, first_media(offers)),
        };
        let mut chosen: Option<(usize, u16)> = None;
        for (group_index, group) in offers.chunks(GROUP).enumerate() {
            let mut parsed: [Option<MediaType<'_>>; GROUP] = [None; GROUP];
            for (slot, offer) in parsed.iter_mut().zip(group) {
                *slot = media::parse(offer.as_bytes(), &Limits::DEFAULT).ok();
            }
            let parsed = parsed.get(..group.len()).unwrap_or(&[]);
            let mut best = [Best::default(); GROUP];
            // The first group's pass also validates every member, so a
            // malformed header is caught before any offer is chosen, in the
            // same walk that scores the offers.
            for element in members.iter() {
                let range = match media::parse_range(element, &self.limits) {
                    Ok(r) => r,
                    Err(e) if group_index == 0 => {
                        let e = locate(e, element, lines.clone());
                        return self.malformed(e, first_media(offers));
                    }
                    Err(_) => continue,
                };
                for (b, offer) in best.iter_mut().zip(parsed) {
                    if let Some(offer) = offer {
                        if range.matches(offer) {
                            b.offer(u16::from(range.specificity()), range.weight());
                        }
                    }
                }
            }
            let base = group_index * GROUP;
            if let Outcome::Chosen { index, weight } = pick(
                best.iter()
                    .take(group.len())
                    .enumerate()
                    .map(|(i, b)| (base + i, b.seen.then_some(b.weight))),
            ) {
                if chosen.is_none_or(|(_, w)| weight.0 > w) {
                    chosen = Some((index, weight.0));
                }
            }
        }
        if offers.is_empty() {
            // No group ran, so validate the members on their own.
            for element in members.iter() {
                if let Err(e) = media::parse_range(element, &self.limits) {
                    return self.malformed(locate(e, element, lines.clone()), None);
                }
            }
        }
        match chosen {
            Some((index, w)) => Outcome::Chosen {
                index,
                weight: QValue(w),
            },
            None => Outcome::NoneAcceptable,
        }
    }

    /// Selects the best of `offers` (language tags such as `"fr-CA"`) for
    /// `Accept-Language`.
    ///
    /// With [`LanguageMatching::Lookup`] (the default), RFC 4647 section
    /// 3.4: the ranges are taken in priority order (highest `q` first,
    /// header order between equals), and each is shortened from its end, a
    /// subtag at a time, until it equals an offer; the first offer found is
    /// chosen, with the `q` of the range that found it. So `en-US` finds
    /// `en` before a lower range is tried, and `*` counts only when no range
    /// follows it in priority. An offer named by a range with `q=0` is never
    /// chosen.
    ///
    /// With [`LanguageMatching::BasicFilter`], a range matches an offer
    /// equal to it or starting with it and `-`, the longest range having
    /// precedence, and `*` matches every offer at the lowest precedence; the
    /// highest weight wins.
    ///
    /// Ties go to the earlier offer. Tags compare ASCII case-insensitively.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{negotiate::{Negotiator, Outcome}, QValue};
    ///
    /// let n = Negotiator::new();
    /// assert_eq!(n.language(Some(b"fr-CA, en;q=0.8"), &["en", "fr"]), Outcome::Chosen { index: 1, weight: QValue::ONE });
    /// // `en-US` comes first and shortens to `en` before `fr` is tried.
    /// assert_eq!(n.language(Some(b"en-US, en;q=0.1, fr;q=0.5"), &["en", "fr"]).index(), Some(0));
    /// // `*` followed by other ranges is skipped.
    /// assert_eq!(n.language(Some(b"*, fr;q=0.5"), &["en", "fr"]).index(), Some(1));
    /// ```
    #[must_use]
    pub fn language(&self, value: Option<&[u8]>, offers: &[&str]) -> Outcome {
        match self.language {
            LanguageMatching::Lookup => self.lookup(value, offers),
            LanguageMatching::BasicFilter => self.weighted(value, offers, filter_rank),
        }
        .unwrap_or_else(|| first(offers))
    }

    /// RFC 4647 section 3.4 lookup over `offers`; `None` for an absent
    /// header.
    ///
    /// Lookup returns the longest truncation of the highest-priority range
    /// that equals an offer. That is the offer whose best (range, truncation)
    /// pair is greatest by: the range's weight, then its earlier position,
    /// then the longer truncation; so each offer is scored against every
    /// range in one walk, with no list sorted or stored.
    fn lookup(&self, value: Option<&[u8]>, offers: &[&str]) -> Option<Outcome> {
        let v = value?;
        let members = match strict_weighted(v, &self.limits, true) {
            Ok(m) => m,
            Err(e) => return Some(self.malformed(e, first(offers).index())),
        };
        let mut chosen: Option<(usize, LookupKey)> = None;
        for (group_index, group) in offers.chunks(GROUP).enumerate() {
            let mut best: [Option<LookupKey>; GROUP] = [None; GROUP];
            let mut refused = [false; GROUP];
            // The last range in priority order (the lowest weight above
            // zero, the latest among equals), and the last `*`: a `*` counts
            // only when it is that range, so it is settled after the walk.
            let mut last: Option<(u16, usize)> = None;
            let mut star: Option<(u16, usize)> = None;
            for (pos, m) in members.iter().enumerate() {
                let weight = m.weight.0;
                if weight == 0 {
                    for (no, offer) in refused.iter_mut().zip(group) {
                        *no |= m.value.eq_ignore_ascii_case(offer.as_bytes());
                    }
                    continue;
                }
                if last.is_none_or(|(w, _)| weight <= w) {
                    last = Some((weight, pos));
                }
                if m.value == b"*" {
                    if star.is_none_or(|(w, _)| weight <= w) {
                        star = Some((weight, pos));
                    }
                    continue;
                }
                for (b, offer) in best.iter_mut().zip(group) {
                    if let Some(reach) = lookup_reach(m.value, offer.as_bytes()) {
                        let key = LookupKey { weight, pos, reach };
                        if b.is_none_or(|k| key.beats(&k)) {
                            *b = Some(key);
                        }
                    }
                }
            }
            // Last in priority, `*` reaches every offer no range reached.
            if let Some((weight, pos)) = star.filter(|s| Some(*s) == last) {
                for b in best.iter_mut().take(group.len()).filter(|b| b.is_none()) {
                    *b = Some(LookupKey {
                        weight,
                        pos,
                        reach: 0,
                    });
                }
            }
            let base = group_index * GROUP;
            for (i, (b, no)) in best.iter().zip(&refused).take(group.len()).enumerate() {
                if let (Some(k), false) = (b, no) {
                    if chosen.is_none_or(|(_, c)| k.beats(&c)) {
                        chosen = Some((base + i, *k));
                    }
                }
            }
        }
        Some(match chosen {
            Some((index, k)) => Outcome::Chosen {
                index,
                weight: QValue(k.weight),
            },
            None => Outcome::NoneAcceptable,
        })
    }

    /// Selects the best of `offers` (content codings such as `"br"`) for
    /// `Accept-Encoding` (RFC 9110 section 12.5.3).
    ///
    /// `identity` is acceptable unless `identity;q=0`, or `*;q=0` without an
    /// explicit `identity`; an empty field value means only `identity` is
    /// acceptable; `x-gzip` equals `gzip` and `x-compress` equals `compress`.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::negotiate::{Negotiator, Outcome};
    ///
    /// let n = Negotiator::new();
    /// assert_eq!(n.encoding(Some(b"x-gzip"), &["br", "gzip"]).index(), Some(1));
    /// assert_eq!(n.encoding(Some(b"*;q=0"), &["gzip", "identity"]), Outcome::NoneAcceptable);
    /// ```
    #[must_use]
    pub fn encoding(&self, value: Option<&[u8]>, offers: &[&str]) -> Outcome {
        let Some(v) = value else {
            return first(offers);
        };
        if text::trim_ows(v).is_empty() {
            return pick(
                offers
                    .iter()
                    .enumerate()
                    .map(|(i, o)| (i, o.eq_ignore_ascii_case("identity").then_some(1000))),
            );
        }
        match self.coding_weights(v, offers, true) {
            Ok(outcome) => outcome,
            Err(e) => self.malformed(e, first(offers).index()),
        }
    }

    /// Selects the best of `offers` (charsets such as `"utf-8"`) for
    /// `Accept-Charset`: as [`encoding`](Self::encoding), without the
    /// `identity` rule.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::negotiate::{Negotiator, Outcome};
    ///
    /// let n = Negotiator::new();
    /// assert_eq!(n.charset(Some(b"utf-8, *;q=0.1"), &["iso-8859-1", "utf-8"]).index(), Some(1));
    /// assert_eq!(n.charset(Some(b"utf-8"), &["iso-8859-1"]), Outcome::NoneAcceptable);
    /// ```
    #[must_use]
    pub fn charset(&self, value: Option<&[u8]>, offers: &[&str]) -> Outcome {
        let Some(v) = value else {
            return first(offers);
        };
        match self.coding_weights(v, offers, false) {
            Ok(outcome) => outcome,
            Err(e) => self.malformed(e, first(offers).index()),
        }
    }

    /// Weights for codings and charsets: an exact match, else `*`, else (for
    /// `identity` under the encoding rules) acceptable unless refused.
    fn coding_weights(
        &self,
        value: &[u8],
        offers: &[&str],
        identity_rule: bool,
    ) -> Result<Outcome> {
        let members = strict_weighted(value, &self.limits, false)?;
        let mut chosen: Option<(usize, u16)> = None;
        for (group_index, group) in offers.chunks(GROUP).enumerate() {
            let mut exact = [None::<u16>; GROUP];
            let mut star = None::<u16>;
            for m in members.iter() {
                if m.value == b"*" {
                    if star.is_none() {
                        star = Some(m.weight.0);
                    }
                    continue;
                }
                let name = canonical(m.value);
                for (slot, offer) in exact.iter_mut().zip(group) {
                    if slot.is_none() && name.eq_ignore_ascii_case(canonical(offer.as_bytes())) {
                        *slot = Some(m.weight.0);
                    }
                }
            }
            let base = group_index * GROUP;
            let outcome = pick(group.iter().enumerate().map(|(i, offer)| {
                let w = exact.get(i).copied().flatten().or(star).or_else(|| {
                    (identity_rule && offer.eq_ignore_ascii_case("identity")).then_some(1000)
                });
                (base + i, w)
            }));
            if let Outcome::Chosen { index, weight } = outcome {
                if chosen.is_none_or(|(_, w)| weight.0 > w) {
                    chosen = Some((index, weight.0));
                }
            }
        }
        Ok(match chosen {
            Some((index, w)) => Outcome::Chosen {
                index,
                weight: QValue(w),
            },
            None => Outcome::NoneAcceptable,
        })
    }

    /// The selection shared by languages: each offer takes the weight of
    /// the member with the highest rank for it (`rank` returns `None` when
    /// a member does not match an offer). `None` for an absent header.
    fn weighted(
        &self,
        value: Option<&[u8]>,
        offers: &[&str],
        rank: impl Fn(&[u8], &[u8]) -> Option<u16>,
    ) -> Option<Outcome> {
        let v = value?;
        let members = match strict_weighted(v, &self.limits, true) {
            Ok(m) => m,
            Err(e) => return Some(self.malformed(e, first(offers).index())),
        };
        let mut chosen: Option<(usize, u16, u16)> = None;
        for (group_index, group) in offers.chunks(GROUP).enumerate() {
            let mut best = [Best::default(); GROUP];
            for m in members.iter() {
                for (b, offer) in best.iter_mut().zip(group) {
                    if let Some(r) = rank(m.value, offer.as_bytes()) {
                        b.offer(r, m.weight);
                    }
                }
            }
            // The highest weight wins; between equal weights the closer
            // match (RFC 4647 lookup returns the longest truncation), then
            // the earlier offer.
            let base = group_index * GROUP;
            for (i, b) in best.iter().take(group.len()).enumerate() {
                if b.seen
                    && b.weight > 0
                    && chosen.is_none_or(|(_, w, r)| (b.weight, b.specificity) > (w, r))
                {
                    chosen = Some((base + i, b.weight, b.specificity));
                }
            }
        }
        Some(match chosen {
            Some((index, w, _)) => Outcome::Chosen {
                index,
                weight: QValue(w),
            },
            None => Outcome::NoneAcceptable,
        })
    }
}

/// `x-gzip` is `gzip` and `x-compress` is `compress` (RFC 9110 section
/// 8.4.1).
fn canonical(c: &[u8]) -> &[u8] {
    if c.eq_ignore_ascii_case(b"x-gzip") {
        b"gzip"
    } else if c.eq_ignore_ascii_case(b"x-compress") {
        b"compress"
    } else {
        c
    }
}

/// Every offer acceptable: the first wins.
fn first(offers: &[&str]) -> Outcome {
    if offers.is_empty() {
        Outcome::NoneAcceptable
    } else {
        Outcome::Chosen {
            index: 0,
            weight: QValue::ONE,
        }
    }
}

/// The first offer that is a valid media type: what an absent `Accept` chooses.
fn first_media(offers: &[&str]) -> Option<usize> {
    offers
        .iter()
        .position(|o| media::parse(o.as_bytes(), &Limits::DEFAULT).is_ok())
}

/// Places an error found inside `element` in the field: an offset from the
/// start of its line, and the line.
fn locate<'a>(e: ParseError, element: &[u8], lines: impl Iterator<Item = &'a [u8]>) -> ParseError {
    let at = element.as_ptr() as usize;
    for (n, line) in lines.enumerate() {
        let start = line.as_ptr() as usize;
        if (start..=start + line.len()).contains(&at) {
            return e.shifted(at - start).on_line(n);
        }
    }
    e
}

/// Where a `language-range` stops being one (RFC 4647 section 2.1:
/// `1*8ALPHA *( "-" 1*8alphanum ) / "*"`); `None` when it is one.
fn language_error(range: &[u8]) -> Option<usize> {
    if range == b"*" {
        return None;
    }
    let (mut at, mut first) = (0usize, true);
    for label in range.split(|&b| b == b'-') {
        let good = |b: &u8| {
            if first {
                b.is_ascii_alphabetic()
            } else {
                b.is_ascii_alphanumeric()
            }
        };
        if let Some(i) = label.iter().position(|b| !good(b)) {
            return Some(at + i);
        }
        if label.is_empty() || label.len() > 8 {
            return Some(at + label.len().min(8));
        }
        first = false;
        at += label.len() + 1;
    }
    None
}

/// [`parse_weighted`] with the grammar of the fields themselves: a member is
/// its value and at most a weight, and with `language` the value is a
/// `language-range`.
fn strict_weighted<'a>(
    value: &'a [u8],
    limits: &Limits,
    language: bool,
) -> Result<WeightedList<'a>> {
    let members = parse_weighted(value, limits)?;
    for e in members.list.iter() {
        let n = text::token_len(e);
        let rest = e.get(n..).unwrap_or(&[]);
        if language {
            if let Some(at) = language_error(e.get(..n).unwrap_or(&[])) {
                return Err(shift_into(
                    ParseError::new(ErrorKind::Malformed, at),
                    value,
                    e,
                ));
            }
        }
        let (params, _) = param::parse(rest, limits).map_err(|x| x.shifted(n))?;
        let only_weight = params
            .iter()
            .enumerate()
            .all(|(i, p)| i == 0 && p.name.eq_ignore_ascii_case(b"q"));
        if !only_weight {
            return Err(shift_into(
                ParseError::new(ErrorKind::TrailingData, n),
                value,
                e,
            ));
        }
    }
    Ok(members)
}

/// Where a range stands in lookup, for one offer it reaches: a higher
/// weight first, then the earlier range, then the longer truncation.
#[derive(Clone, Copy)]
struct LookupKey {
    weight: u16,
    pos: usize,
    reach: usize,
}

impl LookupKey {
    fn beats(&self, other: &Self) -> bool {
        (self.weight, core::cmp::Reverse(self.pos), self.reach)
            > (other.weight, core::cmp::Reverse(other.pos), other.reach)
    }
}

/// RFC 4647 section 3.4: the length of the truncation of `range` that
/// equals `offer`, or `None` when no truncation does. The range shortens a
/// subtag at a time from its end, and a single-character subtag (an
/// extension or private-use singleton) goes with the subtag after it, so no
/// truncation but the whole range ends in one. One pass over the offer's
/// length.
fn lookup_reach(range: &[u8], offer: &[u8]) -> Option<usize> {
    let n = offer.len();
    let head = range.get(..n)?;
    if !head.eq_ignore_ascii_case(offer) {
        return None;
    }
    if n == range.len() {
        return Some(n);
    }
    if n == 0 || range.get(n) != Some(&b'-') {
        return None;
    }
    let last = head.iter().rposition(|&b| b == b'-').map_or(0, |d| d + 1);
    (n - last > 1).then_some(n)
}

/// RFC 4647 section 3.3.1: `range` matches `offer` when they are equal or
/// the offer starts with the range and `-`. Longer ranges rank higher; `*`
/// ranks lowest.
fn filter_rank(range: &[u8], offer: &[u8]) -> Option<u16> {
    if range == b"*" {
        return Some(0);
    }
    let prefix = offer.get(..range.len())?;
    let boundary = offer.len() == range.len() || offer.get(range.len()) == Some(&b'-');
    (prefix.eq_ignore_ascii_case(range) && boundary).then(|| {
        u16::try_from(range.len())
            .unwrap_or(u16::MAX)
            .saturating_add(1)
    })
}

/// Selects the best media type for `Accept` with the defaults.
///
/// `None`: no offer is acceptable (answer 406 or send a default). A header
/// that does not parse is treated as absent.
///
/// # Examples
///
/// ```
/// use parse_net::best_media;
///
/// assert_eq!(best_media(Some(b"text/*;q=0.5, text/html;q=0"), &["text/html"]), None);
/// assert_eq!(best_media(None, &["application/json", "text/html"]), Some(0));
/// ```
#[must_use]
pub fn best_media(accept: Option<&[u8]>, offers: &[&str]) -> Option<usize> {
    Negotiator::new().media(accept, offers).index()
}

/// Selects the best language for `Accept-Language` with RFC 4647 lookup.
///
/// # Examples
///
/// ```
/// use parse_net::best_language;
///
/// assert_eq!(best_language(Some(b"fr-CA, en;q=0.5"), &["en", "fr", "de"]), Some(1));
/// assert_eq!(best_language(Some(b"de"), &["en"]), None);
/// ```
#[must_use]
pub fn best_language(accept_language: Option<&[u8]>, offers: &[&str]) -> Option<usize> {
    Negotiator::new().language(accept_language, offers).index()
}

/// Selects the best content coding for `Accept-Encoding`.
///
/// # Examples
///
/// ```
/// use parse_net::best_encoding;
///
/// assert_eq!(best_encoding(Some(b"gzip;q=1.0, identity; q=0.5, *;q=0"), &["br", "identity"]), Some(1));
/// assert_eq!(best_encoding(Some(b""), &["gzip", "identity"]), Some(1));
/// ```
#[must_use]
pub fn best_encoding(accept_encoding: Option<&[u8]>, offers: &[&str]) -> Option<usize> {
    Negotiator::new().encoding(accept_encoding, offers).index()
}

/// Selects the best charset for `Accept-Charset`.
///
/// # Examples
///
/// ```
/// use parse_net::best_charset;
///
/// assert_eq!(best_charset(Some(b"iso-8859-1;q=0.5, utf-8"), &["iso-8859-1", "utf-8"]), Some(1));
/// ```
#[must_use]
pub fn best_charset(accept_charset: Option<&[u8]>, offers: &[&str]) -> Option<usize> {
    Negotiator::new().charset(accept_charset, offers).index()
}

/// Parses `Accept` into its media ranges.
///
/// # Errors
///
/// The list errors and those of [`media::parse_range`].
///
/// # Examples
///
/// ```
/// use parse_net::{negotiate::parse_accept, Limits};
///
/// let a = parse_accept(b"text/html, */*;q=0.1", &Limits::DEFAULT)?;
/// assert_eq!(a.iter().map(|r| r.weight().thousandths()).collect::<Vec<_>>(), [1000, 100]);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_accept<'a>(value: &'a [u8], limits: &Limits) -> Result<AcceptList<'a>> {
    let l = list::parse(value, limits)?;
    for e in l.iter() {
        media::parse_range(e, limits)
            .map(|_| ())
            .map_err(|err| shift_into(err, value, e))?;
    }
    Ok(AcceptList {
        list: l,
        limits: *limits,
    })
}

/// Re-bases an error found in `element` onto the offsets of `value`.
fn shift_into(e: ParseError, value: &[u8], element: &[u8]) -> ParseError {
    let base = (element.as_ptr() as usize).saturating_sub(value.as_ptr() as usize);
    e.shifted(base)
}

/// The media ranges of a validated `Accept` value.
///
/// # Examples
///
/// ```
/// use parse_net::{negotiate::parse_accept, Limits};
///
/// let a = parse_accept(b"text/html, application/*;q=0.2", &Limits::DEFAULT)?;
/// assert_eq!(a.len(), 2);
/// assert!(a.iter().any(|r| r.subtype() == b"*" && r.weight().thousandths() == 200));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct AcceptList<'a> {
    list: list::List<'a>,
    limits: Limits,
}

impl<'a> AcceptList<'a> {
    /// The ranges, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{negotiate::parse_accept, Limits};
    ///
    /// let a = parse_accept(b"image/webp, image/*;q=0.8", &Limits::DEFAULT)?;
    /// let subtypes: Vec<_> = a.iter().map(|r| r.subtype()).collect();
    /// assert_eq!(subtypes, [&b"webp"[..], &b"*"[..]]);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = media::MediaRange<'a>> + '_ {
        self.list
            .iter()
            .filter_map(|e| media::parse_range(e, &self.limits).ok())
    }

    /// The number of ranges.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{negotiate::parse_accept, Limits};
    ///
    /// assert_eq!(parse_accept(b"text/html, , text/plain", &Limits::DEFAULT)?.len(), 2);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether there are no ranges.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{negotiate::parse_accept, Limits};
    ///
    /// assert!(!parse_accept(b"*/*", &Limits::DEFAULT)?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

/// One member of a weighted list: a value, its weight, and its parameters.
///
/// # Examples
///
/// ```
/// use parse_net::{negotiate::parse_weighted, Limits};
///
/// let w = parse_weighted(b"en-GB;q=0.7", &Limits::DEFAULT)?;
/// let m = w.iter().next().expect("one member");
/// assert_eq!((m.value, m.weight.thousandths(), m.params.len()), (&b"en-GB"[..], 700, 0));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Weighted<'a> {
    /// The value (a coding, a charset, or a language range).
    pub value: &'a [u8],
    /// Its `q`, 1 when absent.
    pub weight: QValue,
    /// The parameters before `q`.
    pub params: Params<'a>,
}

/// Parses `token *( OWS ";" OWS parameter )` members with weights, as in
/// `Accept-Encoding`, `Accept-Charset`, and `Accept-Language`.
///
/// # Errors
///
/// The list errors; [`ErrorKind::NotToken`] for a member that does not start
/// with a token; the parameter errors; [`ErrorKind::InvalidQValue`].
///
/// # Examples
///
/// ```
/// use parse_net::{negotiate::parse_weighted, Limits};
///
/// let w = parse_weighted(b"gzip;q=0.8, br", &Limits::DEFAULT)?;
/// let all: Vec<_> = w.iter().map(|m| (m.value, m.weight.thousandths())).collect();
/// assert_eq!(all, [(&b"gzip"[..], 800), (&b"br"[..], 1000)]);
/// # Ok::<(), parse_net::ParseError>(())
/// ```
pub fn parse_weighted<'a>(value: &'a [u8], limits: &Limits) -> Result<WeightedList<'a>> {
    let l = list::parse(value, limits)?;
    for e in l.iter() {
        weighted_member(e, limits)
            .map(|_| ())
            .map_err(|err| shift_into(err, value, e))?;
    }
    Ok(WeightedList {
        list: l,
        limits: *limits,
    })
}

fn weighted_member<'a>(element: &'a [u8], limits: &Limits) -> Result<Weighted<'a>> {
    let (token, n) =
        text::parse_token(element).map_err(|e| ParseError::new(ErrorKind::NotToken, e.offset()))?;
    let rest = element.get(n..).unwrap_or(&[]);
    let (all, used) = param::parse(rest, limits).map_err(|e| e.shifted(n))?;
    if n + used != element.len() {
        let at = n + used + text::skip_ows(element.get(n + used..).unwrap_or(&[]));
        return err(ErrorKind::NotToken, at);
    }
    let (params, q) = all.split_at_name(b"q");
    let weight = match q {
        None => QValue::ONE,
        Some(p) => match p.value {
            Word::Token(t) => QValue::parse(t).map_err(|e| {
                let at = (t.as_ptr() as usize).saturating_sub(element.as_ptr() as usize);
                ParseError::new(e.kind(), at + e.offset())
            })?,
            Word::Quoted(_) => {
                let at = (p.name.as_ptr() as usize).saturating_sub(element.as_ptr() as usize);
                return err(ErrorKind::InvalidQValue, at);
            }
        },
    };
    Ok(Weighted {
        value: token,
        weight,
        params,
    })
}

/// The members of a validated weighted list.
///
/// # Examples
///
/// ```
/// use parse_net::{negotiate::parse_weighted, Limits};
///
/// let w = parse_weighted(b"utf-8, iso-8859-1;q=0.5", &Limits::DEFAULT)?;
/// assert_eq!(w.len(), 2);
/// assert!(w.iter().all(|m| m.weight.thousandths() >= 500));
/// # Ok::<(), parse_net::ParseError>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct WeightedList<'a> {
    list: list::List<'a>,
    limits: Limits,
}

impl<'a> WeightedList<'a> {
    /// The members, in order.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{negotiate::parse_weighted, Limits};
    ///
    /// let w = parse_weighted(b"gzip;q=0.5, br", &Limits::DEFAULT)?;
    /// let best = w.iter().max_by_key(|m| m.weight).map(|m| m.value);
    /// assert_eq!(best, Some(&b"br"[..]));
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    pub fn iter(&self) -> impl Iterator<Item = Weighted<'a>> + '_ {
        self.list
            .iter()
            .filter_map(|e| weighted_member(e, &self.limits).ok())
    }

    /// The number of members.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{negotiate::parse_weighted, Limits};
    ///
    /// assert_eq!(parse_weighted(b"gzip, deflate, br", &Limits::DEFAULT)?.len(), 3);
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether there are no members.
    ///
    /// # Examples
    ///
    /// ```
    /// use parse_net::{negotiate::parse_weighted, Limits};
    ///
    /// assert!(!parse_weighted(b"identity", &Limits::DEFAULT)?.is_empty());
    /// # Ok::<(), parse_net::ParseError>(())
    /// ```
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qvalue_edge_cases() {
        let ok = |s: &[u8]| QValue::parse(s).map(QValue::thousandths);
        assert_eq!(ok(b"0"), Ok(0));
        assert_eq!(ok(b"0."), Ok(0));
        assert_eq!(ok(b"0.000"), Ok(0));
        assert_eq!(ok(b"0.5"), Ok(500));
        assert_eq!(ok(b"0.05"), Ok(50));
        assert_eq!(ok(b"0.999"), Ok(999));
        assert_eq!(ok(b"1"), Ok(1000));
        assert_eq!(ok(b"1.000"), Ok(1000));
        for bad in [
            &b"1.001"[..],
            b"0.0001",
            b".5",
            b"-1",
            b"1.5",
            b"",
            b"2",
            b"0,5",
            b"0.5x",
        ] {
            assert_eq!(
                QValue::parse(bad).unwrap_err().kind(),
                ErrorKind::InvalidQValue
            );
        }
        assert_eq!(QValue::from_thousandths(1001), None);
        assert_eq!(
            QValue::from_thousandths(250).map(QValue::thousandths),
            Some(250)
        );
    }

    #[test]
    fn test_media_negotiation_cases() {
        let n = Negotiator::new();
        let i = |h: &[u8], o: &[&str]| n.media(Some(h), o).index();
        assert_eq!(
            i(b"*/*;q=0, text/html", &["text/html", "text/plain"]),
            Some(0)
        );
        assert_eq!(
            i(b"text/*;q=0.5, text/html;q=0", &["text/html", "text/plain"]),
            Some(1)
        );
        assert_eq!(
            i(
                b"text/html;level=1, text/html;q=0.1",
                &["text/html", "text/html;level=1"]
            ),
            Some(1)
        );
        assert_eq!(
            i(
                b"application/json;q=0.5, text/html;q=0.5",
                &["text/html", "application/json"]
            ),
            Some(0)
        );
        assert_eq!(i(b"", &["text/html"]), None);
        assert_eq!(i(b"TEXT/HTML", &["text/html"]), Some(0));
        assert_eq!(
            i(b"text/html;charset=UTF-8", &["text/html;charset=utf-8"]),
            Some(0)
        );
        assert_eq!(i(b"text/html;level=1", &["text/html;level=2"]), None);
        assert_eq!(n.media(None, &[]), Outcome::NoneAcceptable);
        assert_eq!(i(b"*/*", &["not a media type", "text/html"]), Some(1));
    }

    #[test]
    fn test_media_malformed_policies() {
        let bad = Some(&b"text/html;q=2"[..]);
        assert_eq!(
            Negotiator::new().media(bad, &["a/b"]),
            Outcome::HeaderIgnored { index: 0 }
        );
        assert_eq!(Negotiator::new().media(bad, &[]), Outcome::NoneAcceptable);
        let refused = Negotiator::new()
            .on_malformed(MalformedPolicy::Refuse)
            .media(bad, &["a/b"]);
        assert!(matches!(refused, Outcome::Refused(e) if e.kind() == ErrorKind::InvalidQValue));
    }

    #[test]
    fn test_media_more_than_one_group_of_offers() {
        let names: std::vec::Vec<std::string::String> =
            (0..70).map(|i| std::format!("type/s{i}")).collect();
        let offers: std::vec::Vec<&str> = names.iter().map(std::string::String::as_str).collect();
        assert_eq!(
            Negotiator::new().media(Some(b"type/s65"), &offers).index(),
            Some(65)
        );
        assert_eq!(
            Negotiator::new()
                .media(Some(b"type/s65;q=0.5, type/s3;q=0.4"), &offers)
                .index(),
            Some(65)
        );
        assert_eq!(
            Negotiator::new().media(Some(b"type/*"), &offers).index(),
            Some(0)
        );
    }

    #[test]
    fn test_language_lookup_and_filter() {
        let n = Negotiator::new();
        let i = |h: &[u8], o: &[&str]| n.language(Some(h), o).index();
        assert_eq!(i(b"en-US", &["fr", "en"]), Some(1));
        assert_eq!(i(b"EN-us", &["en-US"]), Some(0));
        assert_eq!(i(b"zh-Hant-CN-x-private1", &["zh", "zh-Hant"]), Some(1));
        assert_eq!(i(b"*", &["de", "fr"]), Some(0));
        assert_eq!(i(b"en-US, en;q=0", &["en"]), None);
        assert_eq!(i(b"fr;q=0.5, en;q=0.9", &["fr", "en"]), Some(1));
        assert_eq!(i(b"en", &["en-US"]), None);
        let f = Negotiator::new().language_matching(LanguageMatching::BasicFilter);
        assert_eq!(f.language(Some(b"en"), &["en-US"]).index(), Some(0));
        assert_eq!(f.language(Some(b"en"), &["eng"]).index(), None);
        assert_eq!(
            f.language(Some(b"de-DE;q=0.9, de;q=0.1"), &["de-DE-1996"]),
            Outcome::Chosen {
                index: 0,
                weight: QValue(900)
            }
        );
        assert_eq!(n.language(None, &["en"]).index(), Some(0));
    }

    #[test]
    fn test_encoding_identity_rules() {
        let e = |h: &[u8], o: &[&str]| best_encoding(Some(h), o);
        assert_eq!(e(b"gzip", &["identity"]), Some(0));
        assert_eq!(e(b"gzip, identity;q=0", &["identity"]), None);
        assert_eq!(e(b"*;q=0", &["identity"]), None);
        assert_eq!(e(b"*;q=0, identity", &["br", "identity"]), Some(1));
        assert_eq!(e(b"x-gzip", &["br", "gzip"]), Some(1));
        assert_eq!(e(b"gzip;q=0.5, *;q=0.9", &["gzip", "br"]), Some(1));
        assert_eq!(e(b"   ", &["gzip", "identity"]), Some(1));
        assert_eq!(best_encoding(None, &["br"]), Some(0));
        assert_eq!(e(b"gzip;q=x", &["br", "gzip"]), Some(0));
    }

    #[test]
    fn test_charset_rules() {
        assert_eq!(best_charset(Some(b"utf-8"), &["iso-8859-1"]), None);
        assert_eq!(best_charset(Some(b"*;q=0.1"), &["iso-8859-1"]), Some(0));
        assert_eq!(best_charset(Some(b""), &["utf-8"]), None);
    }

    #[test]
    fn test_weighted_member_errors() {
        let l = Limits::DEFAULT;
        assert_eq!(
            parse_weighted(b"gzip;q=\"1\"", &l).unwrap_err().kind(),
            ErrorKind::InvalidQValue
        );
        assert_eq!(
            parse_weighted(b"gzip x", &l).unwrap_err().kind(),
            ErrorKind::NotToken
        );
        assert_eq!(
            parse_weighted(b"@", &l).unwrap_err().kind(),
            ErrorKind::NotToken
        );
        let e = parse_weighted(b"br, gzip;q=7", &l).unwrap_err();
        assert_eq!((e.kind(), e.offset()), (ErrorKind::InvalidQValue, 11));
        assert_eq!(
            parse_weighted(b"a;q=1;q=0", &l).unwrap_err().kind(),
            ErrorKind::DuplicateParameter
        );
        assert_eq!(parse_accept(b"text/html;q=2", &l).unwrap_err().offset(), 12);
    }

    #[test]
    fn test_members_times_offers_is_bounded() {
        let mut v = std::vec::Vec::new();
        for i in 0..1024 {
            v.extend_from_slice(std::format!("t{i}/x;q=0.5,").as_bytes());
        }
        v.truncate(v.len() - 1);
        let names: std::vec::Vec<std::string::String> =
            (0..32).map(|i| std::format!("t{i}/x")).collect();
        let offers: std::vec::Vec<&str> = names.iter().map(std::string::String::as_str).collect();
        assert_eq!(best_media(Some(&v), &offers), Some(0));
    }
}
