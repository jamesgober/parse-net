//! The httpwg structured-field-tests suite (RFC 9651 parsing), vendored in
//! `tests/sfv` with its license. Every case must give the expected result:
//! `must_fail` cases must be refused, `can_fail` cases may be refused, and
//! every accepted case must match `expected` exactly.

use parse_net::sfv::{self, BareItem, Item, Member, SfParams};
use serde_json::Value;

/// The files in the suite that test parsing.
const FILES: &[&str] = &[
    "binary",
    "boolean",
    "date",
    "dictionary",
    "display-string",
    "examples",
    "item",
    "key-generated",
    "large-generated",
    "list",
    "listlist",
    "number-generated",
    "number",
    "param-dict",
    "param-list",
    "param-listlist",
    "string-generated",
    "string",
    "token-generated",
    "token",
];

fn b32_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes().filter(|&c| c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => panic!("base32 {c}"),
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn b64_decode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in s.iter().filter(|&&c| c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("base64 {c}"),
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn bare_eq(ours: BareItem<'_>, want: &Value) -> Result<(), String> {
    let ok = match (ours, want) {
        (BareItem::Integer(i), Value::Number(n)) if n.is_i64() => n.as_i64() == Some(i),
        (BareItem::Decimal(d), Value::Number(n)) if !n.is_i64() => {
            n.as_f64().map(|f| (f * 1000.0).round() as i64) == Some(d.thousandths())
        }
        (BareItem::String(s), Value::String(w)) => {
            assert_eq!(s.unescaped_len(), w.len());
            let mut buf = vec![0u8; s.unescaped_len()];
            s.eq_str(w) && s.unescape_into(&mut buf).map_err(|e| e.to_string())? == w
        }
        (BareItem::Boolean(b), Value::Bool(w)) => b == *w,
        (b, Value::Object(o)) => {
            let ty = o["__type"].as_str().unwrap_or("");
            let v = &o["value"];
            match (b, ty) {
                (BareItem::Token(t), "token") => v.as_str() == Some(t),
                (BareItem::Date(d), "date") => v.as_i64() == Some(d),
                (BareItem::ByteSeq(s), "binary") => {
                    let want = b32_decode(v.as_str().unwrap_or(""));
                    s.decoded_len() == want.len() && b64_decode(s.raw()) == want
                }
                (BareItem::DisplayString(s), "displaystring") => {
                    let mut buf = vec![0u8; s.decoded_len()];
                    s.decode_into(&mut buf).map_err(|e| e.to_string())? == v.as_str().unwrap_or("")
                }
                _ => false,
            }
        }
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("bare {ours:?} != {want}"))
    }
}

/// An ordered map in which a repeated key overwrites the value in place, as
/// RFC 9651 sections 4.2.2 and 4.2.3.2 define it.
fn ordered<K: PartialEq, V>(pairs: impl Iterator<Item = (K, V)>) -> Vec<(K, V)> {
    let mut out: Vec<(K, V)> = Vec::new();
    for (k, v) in pairs {
        match out.iter_mut().find(|(ok, _)| *ok == k) {
            Some(slot) => slot.1 = v,
            None => out.push((k, v)),
        }
    }
    out
}

fn params_eq(ours: SfParams<'_>, want: &Value) -> Result<(), String> {
    let want = want.as_array().ok_or("params")?;
    let got = ordered(ours.iter());
    if got.len() != want.len() {
        return Err(format!("{} params, want {}", got.len(), want.len()));
    }
    for ((k, v), w) in got.iter().zip(want) {
        if w[0].as_str() != Some(k) {
            return Err(format!("param key {k} != {}", w[0]));
        }
        bare_eq(*v, &w[1])?;
    }
    Ok(())
}

fn item_eq(ours: Item<'_>, want: &Value) -> Result<(), String> {
    bare_eq(ours.bare, &want[0])?;
    params_eq(ours.params, &want[1])
}

fn member_eq(ours: Member<'_>, want: &Value) -> Result<(), String> {
    match ours {
        Member::Item(i) => item_eq(i, want),
        Member::InnerList(l) => {
            let items = want[0].as_array().ok_or("not an inner list")?;
            let got: Vec<Item<'_>> = l.iter().collect();
            if got.len() != items.len() || l.len() != items.len() {
                return Err(format!("{} inner items, want {}", got.len(), items.len()));
            }
            for (g, w) in got.into_iter().zip(items) {
                item_eq(g, w)?;
            }
            params_eq(l.params(), &want[1])
        }
    }
}

fn members_eq<'a>(got: impl Iterator<Item = Member<'a>>, want: &Value) -> Result<(), String> {
    let want = want.as_array().ok_or("members")?;
    let got: Vec<Member<'_>> = got.collect();
    if got.len() != want.len() {
        return Err(format!("{} members, want {}", got.len(), want.len()));
    }
    got.into_iter()
        .zip(want)
        .try_for_each(|(g, w)| member_eq(g, w))
}

fn dict_eq<'a>(
    got: impl Iterator<Item = (&'a str, Member<'a>)>,
    want: &Value,
) -> Result<(), String> {
    let want = want.as_array().ok_or("dictionary")?;
    let got = ordered(got);
    if got.len() != want.len() {
        return Err(format!("{} keys, want {}", got.len(), want.len()));
    }
    for ((k, m), w) in got.into_iter().zip(want) {
        if w[0].as_str() != Some(k) {
            return Err(format!("key {k} != {}", w[0]));
        }
        member_eq(m, &w[1])?;
    }
    Ok(())
}

/// Splits a valid list or dictionary at its top-level commas (outside
/// strings, Display Strings, and inner lists), one member per line, OWS
/// trimmed. Empty for an empty field.
fn member_lines(v: &[u8]) -> Vec<Vec<u8>> {
    let mut parts = Vec::new();
    let (mut start, mut depth, mut quoted, mut escaped) = (0usize, 0u32, false, false);
    for (i, &b) in v.iter().enumerate() {
        if quoted {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => quoted = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => quoted = true,
            b'(' => depth += 1,
            b')' => depth -= 1,
            b',' if depth == 0 => {
                parts.push(v[start..i].to_vec());
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(v[start..].to_vec());
    let trim = |p: Vec<u8>| {
        let s = p
            .iter()
            .position(|&b| b != b' ' && b != b'\t')
            .unwrap_or(p.len());
        let e = p
            .iter()
            .rposition(|&b| b != b' ' && b != b'\t')
            .map_or(s, |e| e + 1);
        p[s..e].to_vec()
    };
    let parts: Vec<Vec<u8>> = parts.into_iter().map(trim).collect();
    if parts.len() == 1 && parts[0].is_empty() {
        Vec::new()
    } else {
        parts
    }
}

/// Parses `raw` as `ty` and compares with `expected`; `Err(None)` when the
/// parser refused it.
fn run(ty: &str, raw: &[Vec<u8>], expected: Option<&Value>) -> Result<(), Option<String>> {
    let joined = raw.join(&b", "[..]);
    let lines: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
    let cmp = |r: Result<(), String>| r.map_err(Some);
    match ty {
        "item" => {
            let i = sfv::parse_item(&joined).map_err(|_| None)?;
            expected.map_or(Ok(()), |w| cmp(item_eq(i, w)))
        }
        "list" => {
            let l = sfv::parse_list(&joined).map_err(|_| None)?;
            let ok = expected.map_or(Ok(()), |w| cmp(members_eq(l.iter(), w)));
            // The multi-line API agrees with the joined value, except that
            // it refuses an empty line, which joining hides only when the
            // field has a single line.
            match sfv::parse_list_lines(&lines) {
                Ok(ll) => {
                    expected.map_or(Ok(()), |w| cmp(members_eq(ll.iter(), w)))?;
                    assert_eq!(ll.len(), l.len());
                }
                Err(_) => assert!(lines.len() == 1 && lines[0].iter().all(|&b| b == b' ')),
            }
            // One line per member gives the same members (section 12.2).
            let parts = member_lines(&joined);
            if !parts.is_empty() {
                let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
                let ll = sfv::parse_list_lines(&refs).map_err(|e| Some(format!("split: {e}")))?;
                expected.map_or(Ok(()), |w| cmp(members_eq(ll.iter(), w)))?;
            }
            ok
        }
        "dictionary" => {
            let d = sfv::parse_dictionary(&joined).map_err(|_| None)?;
            let ok = expected.map_or(Ok(()), |w| cmp(dict_eq(d.iter(), w)));
            match sfv::parse_dictionary_lines(&lines) {
                Ok(dl) => {
                    expected.map_or(Ok(()), |w| cmp(dict_eq(dl.iter(), w)))?;
                    assert_eq!(dl.len(), d.len());
                }
                Err(_) => assert!(lines.len() == 1 && lines[0].iter().all(|&b| b == b' ')),
            }
            let parts = member_lines(&joined);
            if !parts.is_empty() {
                let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
                let dl =
                    sfv::parse_dictionary_lines(&refs).map_err(|e| Some(format!("split: {e}")))?;
                expected.map_or(Ok(()), |w| cmp(dict_eq(dl.iter(), w)))?;
            }
            ok
        }
        other => panic!("header type {other}"),
    }
}

#[test]
fn test_sfv_conformance_suite() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/sfv");
    let (mut cases, mut accepted, mut failures) = (0usize, 0usize, Vec::new());
    for file in FILES {
        let text = std::fs::read_to_string(format!("{dir}/{file}.json")).expect("suite file");
        let suite: Vec<Value> = serde_json::from_str(&text).expect("json");
        for case in &suite {
            cases += 1;
            let name = format!("{file}: {}", case["name"].as_str().unwrap_or("?"));
            let ty = case["header_type"].as_str().unwrap_or("");
            let raw: Vec<Vec<u8>> = case["raw"]
                .as_array()
                .expect("raw")
                .iter()
                .map(|l| {
                    // The suite stores bytes as JSON strings of code points
                    // 0 to 255.
                    l.as_str()
                        .expect("raw line")
                        .chars()
                        .map(|c| u8::try_from(u32::from(c)).expect("byte"))
                        .collect()
                })
                .collect();
            let must_fail = case["must_fail"].as_bool().unwrap_or(false);
            let can_fail = case["can_fail"].as_bool().unwrap_or(false);
            let result = run(ty, &raw, case.get("expected"));
            accepted += usize::from(result.is_ok());
            match (result, must_fail, can_fail) {
                (Ok(()), false, _) | (Err(None), true, _) | (Err(None), _, true) => {}
                (Ok(()), true, _) => failures.push(format!("{name}: accepted, must fail")),
                (Err(None), false, false) => failures.push(format!("{name}: refused")),
                (Err(Some(why)), _, _) => failures.push(format!("{name}: {why}")),
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {cases} failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
    // The suite at the vendored commit: 1598 cases, 866 `must_fail`. Of the
    // 8 `can_fail` cases, 4 are refused: partial and extra base64 padding,
    // and the two Dates outside years 1 to 9999 (D-030, D-050).
    assert_eq!((cases, accepted), (1598, 728));
}
