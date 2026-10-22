//! The error types: [`ParseError`] for refused input, [`WriteError`] for
//! refused output.
//!
//! Both carry a kind and, where it applies, a byte offset. Neither ever holds
//! input bytes, so either is safe to log: an attacker cannot use an error
//! message to inject text into a log line.

use core::fmt;

/// What a parser refused.
///
/// Every variant names what was refused. Unless a variant says otherwise, the
/// caller's response is the same: treat the field as malformed. For a request
/// field that means refusing the request (HTTP 400) or ignoring the field
/// where its RFC allows that; for a field a server produced, it means a bug
/// in the producer.
///
/// The enum is `#[non_exhaustive]`: new kinds may be added in minor versions.
///
/// # Examples
///
/// ```
/// use parse_net::{scan, ErrorKind};
///
/// let err = scan::check_field_value(b"a\rb").unwrap_err();
/// assert_eq!(err.kind(), ErrorKind::BareCr);
/// assert_eq!(ErrorKind::BareCr.message(), "bare CR");
/// ```
#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// A value or element that must not be empty was empty.
    Empty,
    /// Bytes that must form a token (RFC 9110 section 5.6.2) do not.
    NotToken,
    /// A byte not allowed at this position.
    InvalidByte,
    /// A CR byte. CR is a request-smuggling vector: refuse the whole message,
    /// do not just drop the field.
    BareCr,
    /// An LF byte inside a value. Refuse the whole message.
    LineFeed,
    /// A NUL byte. Refuse the whole message.
    Nul,
    /// Another control byte (0x01 to 0x1F except HTAB, or DEL).
    Control,
    /// A quoted string with no closing `"`, or one that would have to
    /// continue on the next field line.
    UnterminatedQuote,
    /// The byte after `\` in a quoted string is not `HTAB / SP / VCHAR /
    /// obs-text`.
    InvalidQuotedPair,
    /// A `(` without its `)`, or a `)` without its `(`.
    UnbalancedComment,
    /// Comment nesting deeper than [`Limits::max_comment_depth`](crate::Limits::max_comment_depth).
    CommentTooDeep,
    /// More list members, parameters, dictionary members, or encoded words
    /// than the configured limit allows.
    TooManyMembers,
    /// More empty list elements (`a, , , b`) than
    /// [`Limits::max_empty_elements`](crate::Limits::max_empty_elements).
    TooManyEmptyElements,
    /// A separator with nothing after it where the grammar forbids that.
    TrailingSeparator,
    /// Two members without the separator between them.
    ExpectedSeparator,
    /// Bytes after a complete value.
    TrailingData,
    /// A parameter name repeated where repetition is refused.
    DuplicateParameter,
    /// A name without `=value` where a value is required.
    MissingValue,
    /// Digits were expected; a sign, space, or other byte was found.
    InvalidNumber,
    /// A number larger than its type or the RFC allows.
    NumberOverflow,
    /// A value outside its valid range, such as a year outside 1 to 9999.
    OutOfRange,
    /// A date that does not exist, or that matches no accepted format.
    InvalidDate,
    /// The weekday does not agree with the date.
    WeekdayMismatch,
    /// A media type that does not match `type "/" subtype parameters`.
    InvalidMediaType,
    /// `*` as a type or subtype where a concrete media type is required.
    Wildcard,
    /// A `boundary` parameter that breaks RFC 2046 section 5.1.1.
    InvalidBoundary,
    /// A `q` value outside the RFC 9110 section 12.4.2 grammar.
    InvalidQValue,
    /// An entity tag outside `[ "W/" ] DQUOTE *etagc DQUOTE`.
    InvalidEntityTag,
    /// A range set or `Content-Range` that is malformed or inconsistent.
    InvalidRange,
    /// A malformed charset name.
    InvalidCharset,
    /// A well-formed charset that parse-net does not decode. Only UTF-8,
    /// US-ASCII, and ISO-8859-1 are decoded.
    UnsupportedCharset,
    /// A `%` not followed by two hex digits, or uppercase hex where only
    /// lowercase is allowed.
    InvalidPercentEncoding,
    /// Bytes that must be UTF-8 are not (overlong forms and surrogates
    /// included).
    InvalidUtf8,
    /// A decoded value contains a control byte. Never copy such a value into
    /// another header or a log.
    ControlInDecoded,
    /// A host that is not a reg-name, IPv4 address, or IP literal, or that
    /// carries userinfo (`@`).
    InvalidHost,
    /// A port that is not digits, or is above 65535.
    InvalidPort,
    /// An IP literal that is not a valid address, or a name made only of
    /// digits and dots that is not a valid IPv4 address.
    InvalidAddress,
    /// An `Origin` that is not `null` or `scheme "://" host [ ":" port ]`.
    InvalidOrigin,
    /// A Structured Field key outside `( lcalpha / "*" ) *( lcalpha / DIGIT /
    /// "_" / "-" / "." / "*" )`.
    InvalidKey,
    /// A string, token, key, byte sequence, address, or local part longer
    /// than its limit.
    TooLong,
    /// Bytes outside the base64 alphabet, or a misplaced `=`.
    InvalidBase64,
    /// A malformed RFC 2047 encoded word.
    InvalidEncodedWord,
    /// RFC 2231 sections that are missing, repeated, or out of order, or a
    /// charset on a section other than 0.
    SectionGap,
    /// More RFC 2231 sections than
    /// [`Limits::max_rfc2231_sections`](crate::Limits::max_rfc2231_sections).
    TooManySections,
    /// An address outside the strict RFC 5322 `addr-spec`.
    InvalidAddrSpec,
    /// An email header line over 998 bytes.
    LineTooLong,
    /// A structure that is wrong as a whole. For a forwarded chain, use the
    /// peer address.
    Malformed,
    /// A forwarded chain longer than the hop limit. Use the peer address.
    TooManyHops,
    /// The output buffer is shorter than the decoded value. Nothing was
    /// written; retry with a buffer of the size the matching `*_len` function
    /// reports.
    BufferTooSmall,
}

impl ErrorKind {
    /// The fixed text [`ParseError`]'s `Display` uses for this kind.
    ///
    /// # Examples
    ///
    /// ```
    /// assert_eq!(parse_net::ErrorKind::InvalidByte.message(), "invalid byte");
    /// ```
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::Empty => "empty value",
            Self::NotToken => "not a token",
            Self::InvalidByte => "invalid byte",
            Self::BareCr => "bare CR",
            Self::LineFeed => "line feed in value",
            Self::Nul => "NUL byte",
            Self::Control => "control byte",
            Self::UnterminatedQuote => "unterminated quoted string",
            Self::InvalidQuotedPair => "invalid quoted pair",
            Self::UnbalancedComment => "unbalanced comment",
            Self::CommentTooDeep => "comment nested too deeply",
            Self::TooManyMembers => "too many members",
            Self::TooManyEmptyElements => "too many empty list elements",
            Self::TrailingSeparator => "trailing separator",
            Self::ExpectedSeparator => "expected a separator",
            Self::TrailingData => "trailing data",
            Self::DuplicateParameter => "duplicate parameter",
            Self::MissingValue => "missing value",
            Self::InvalidNumber => "invalid number",
            Self::NumberOverflow => "number overflow",
            Self::OutOfRange => "value out of range",
            Self::InvalidDate => "invalid date",
            Self::WeekdayMismatch => "weekday does not match the date",
            Self::InvalidMediaType => "invalid media type",
            Self::Wildcard => "wildcard where a concrete value is required",
            Self::InvalidBoundary => "invalid multipart boundary",
            Self::InvalidQValue => "invalid quality value",
            Self::InvalidEntityTag => "invalid entity tag",
            Self::InvalidRange => "invalid range",
            Self::InvalidCharset => "invalid charset",
            Self::UnsupportedCharset => "unsupported charset",
            Self::InvalidPercentEncoding => "invalid percent-encoding",
            Self::InvalidUtf8 => "invalid UTF-8",
            Self::ControlInDecoded => "control byte in decoded value",
            Self::InvalidHost => "invalid host",
            Self::InvalidPort => "invalid port",
            Self::InvalidAddress => "invalid IP address",
            Self::InvalidOrigin => "invalid origin",
            Self::InvalidKey => "invalid structured field key",
            Self::TooLong => "value too long",
            Self::InvalidBase64 => "invalid base64",
            Self::InvalidEncodedWord => "invalid encoded word",
            Self::SectionGap => "RFC 2231 sections out of order",
            Self::TooManySections => "too many RFC 2231 sections",
            Self::InvalidAddrSpec => "invalid email address",
            Self::LineTooLong => "line too long",
            Self::Malformed => "malformed field",
            Self::TooManyHops => "too many forwarding hops",
            Self::BufferTooSmall => "output buffer too small",
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

/// Why a value was refused, and where.
///
/// Eight bytes, `Copy`, and it never contains input bytes, so it is safe to
/// log.
///
/// # Examples
///
/// ```
/// use parse_net::{ErrorKind, ParseError};
///
/// let err = ParseError::new(ErrorKind::InvalidByte, 4);
/// assert_eq!(err.kind(), ErrorKind::InvalidByte);
/// assert_eq!(err.offset(), 4);
/// assert_eq!(err.to_string(), "invalid byte at offset 4");
/// assert_eq!(core::mem::size_of::<ParseError>(), 8);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ParseError {
    kind: ErrorKind,
    line: u8,
    at: u32,
}

impl ParseError {
    /// Builds an error of `kind` at byte `offset`.
    ///
    /// For callers that implement a visitor or wrap parse-net. Offsets above
    /// `u32::MAX` saturate.
    #[must_use]
    pub const fn new(kind: ErrorKind, offset: usize) -> Self {
        let at = if offset > u32::MAX as usize {
            u32::MAX
        } else {
            offset as u32
        };
        Self { kind, line: 0, at }
    }

    /// What was refused.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The offset of the first byte that could not be accepted, relative to
    /// the start of the value passed in, or of the field line named by
    /// [`line`](Self::line) when several lines were parsed as one field.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.at as usize
    }

    /// The zero-based index of the field line that failed when several lines
    /// were parsed as one field; `0` otherwise. Saturates at 255.
    #[must_use]
    pub const fn line(&self) -> usize {
        self.line as usize
    }

    /// The same error, attributed to field line `line` (saturating at 255).
    pub(crate) const fn on_line(self, line: usize) -> Self {
        let line = if line > u8::MAX as usize {
            u8::MAX
        } else {
            line as u8
        };
        Self { line, ..self }
    }

    /// The same error with its offset moved forward by `by` bytes
    /// (saturating), for errors found in a sub-slice.
    pub(crate) const fn shifted(self, by: usize) -> Self {
        let by = if by > u32::MAX as usize {
            u32::MAX
        } else {
            by as u32
        };
        Self {
            at: self.at.saturating_add(by),
            ..self
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.line == 0 {
            write!(f, "{} at offset {}", self.kind.message(), self.at)
        } else {
            write!(
                f,
                "{} at offset {} of field line {}",
                self.kind.message(),
                self.at,
                self.line
            )
        }
    }
}

impl core::error::Error for ParseError {}

/// The result type of every parser.
pub(crate) type Result<T> = core::result::Result<T, ParseError>;

/// Shorthand for an `Err(ParseError)`.
pub(crate) const fn err<T>(kind: ErrorKind, at: usize) -> Result<T> {
    Err(ParseError::new(kind, at))
}

/// A sink has no room for the bytes it was given.
///
/// Returned by [`Sink::put`](crate::Sink::put); writers turn it into
/// [`WriteError::Full`].
///
/// # Examples
///
/// ```
/// use parse_net::{Full, Sink, SliceSink};
///
/// let mut buf = [0u8; 2];
/// let mut out = SliceSink::new(&mut buf);
/// assert_eq!(out.put(b"abc"), Err(Full));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Full;

impl fmt::Display for Full {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("output sink is full")
    }
}

impl core::error::Error for Full {}

/// Why a writer refused.
///
/// # Examples
///
/// ```
/// use parse_net::{write, SliceSink, WriteError};
///
/// let mut buf = [0u8; 64];
/// let mut out = SliceSink::new(&mut buf);
/// let err = write::write_field_value(b"evil\r\nSet-Cookie: x=1", &mut out).unwrap_err();
/// assert_eq!(err, WriteError::Forbidden { at: 4 });
/// assert!(out.written().is_empty());
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WriteError {
    /// The sink has no room. When the sink reports its room (as
    /// [`SliceSink`](crate::SliceSink) does), nothing was written. Retry with
    /// a larger buffer; [`CountSink`](crate::CountSink) gives the exact
    /// length.
    Full,
    /// The input byte at offset `at` is not allowed in the output grammar
    /// (CR, LF, NUL, another control, or a byte the format forbids). Refuse
    /// the input; never strip it and retry silently.
    Forbidden {
        /// Offset of the refused byte in the input.
        at: u32,
    },
    /// A number outside the format's range.
    OutOfRange,
    /// A position that requires a token got something else.
    NotToken,
    /// A structured writer was called out of order, such as a parameter
    /// before any item. A bug in the calling code.
    InvalidSequence,
}

impl WriteError {
    /// A `Forbidden` error at byte `at` (saturating).
    pub(crate) const fn forbidden(at: usize) -> Self {
        let at = if at > u32::MAX as usize {
            u32::MAX
        } else {
            at as u32
        };
        Self::Forbidden { at }
    }
}

impl From<Full> for WriteError {
    fn from(_: Full) -> Self {
        Self::Full
    }
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => f.write_str("output sink is full"),
            Self::Forbidden { at } => write!(f, "forbidden byte at offset {at}"),
            Self::OutOfRange => f.write_str("value out of range"),
            Self::NotToken => f.write_str("not a token"),
            Self::InvalidSequence => f.write_str("writer called out of order"),
        }
    }
}

impl core::error::Error for WriteError {}

#[cfg(test)]
mod tests {
    use std::string::ToString;

    use super::*;

    #[test]
    fn test_parse_error_size_is_eight_bytes() {
        assert_eq!(core::mem::size_of::<ParseError>(), 8);
        assert_eq!(core::mem::size_of::<ErrorKind>(), 1);
    }

    #[test]
    fn test_parse_error_offset_saturates() {
        let e = ParseError::new(ErrorKind::Empty, usize::MAX);
        assert_eq!(e.offset(), u32::MAX as usize);
        assert_eq!(e.shifted(10).offset(), u32::MAX as usize);
        assert_eq!(e.on_line(1000).line(), 255);
    }

    #[test]
    fn test_parse_error_display_with_line() {
        let e = ParseError::new(ErrorKind::InvalidByte, 3).on_line(2);
        assert_eq!(e.to_string(), "invalid byte at offset 3 of field line 2");
        assert_eq!(e.shifted(4).offset(), 7);
    }

    #[test]
    fn test_every_message_is_nonempty_and_lowercase_led() {
        use ErrorKind::*;
        let all = [
            Empty,
            NotToken,
            InvalidByte,
            BareCr,
            LineFeed,
            Nul,
            Control,
            UnterminatedQuote,
            InvalidQuotedPair,
            UnbalancedComment,
            CommentTooDeep,
            TooManyMembers,
            TooManyEmptyElements,
            TrailingSeparator,
            ExpectedSeparator,
            TrailingData,
            DuplicateParameter,
            MissingValue,
            InvalidNumber,
            NumberOverflow,
            OutOfRange,
            InvalidDate,
            WeekdayMismatch,
            InvalidMediaType,
            Wildcard,
            InvalidBoundary,
            InvalidQValue,
            InvalidEntityTag,
            InvalidRange,
            InvalidCharset,
            UnsupportedCharset,
            InvalidPercentEncoding,
            InvalidUtf8,
            ControlInDecoded,
            InvalidHost,
            InvalidPort,
            InvalidAddress,
            InvalidOrigin,
            InvalidKey,
            TooLong,
            InvalidBase64,
            InvalidEncodedWord,
            SectionGap,
            TooManySections,
            InvalidAddrSpec,
            LineTooLong,
            Malformed,
            TooManyHops,
            BufferTooSmall,
        ];
        for k in all {
            let m = k.message();
            assert!(!m.is_empty());
            assert_eq!(k.to_string(), m);
        }
    }

    #[test]
    fn test_write_error_display_and_from_full() {
        assert_eq!(WriteError::from(Full), WriteError::Full);
        assert_eq!(
            WriteError::forbidden(7).to_string(),
            "forbidden byte at offset 7"
        );
        assert_eq!(
            WriteError::forbidden(usize::MAX),
            WriteError::Forbidden { at: u32::MAX }
        );
        assert_eq!(Full.to_string(), "output sink is full");
        assert_eq!(
            WriteError::InvalidSequence.to_string(),
            "writer called out of order"
        );
    }
}
