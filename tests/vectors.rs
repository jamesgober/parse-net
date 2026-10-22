//! RFC test vectors, stored as data files in `tests/vectors/` so they run the
//! same on every platform. Each line is `expected<TAB>input`; `#` starts a
//! comment line; `\t` and `\xNN` in the input are expanded.

use parse_net::{self as pn, ErrorKind, Host};

fn unescape(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match (b[i], b.get(i + 1)) {
            (b'\\', Some(b't')) => {
                out.push(b'\t');
                i += 2;
            }
            (b'\\', Some(b'x')) => {
                let hex = std::str::from_utf8(&b[i + 2..i + 4]).expect("ascii");
                out.push(u8::from_str_radix(hex, 16).expect("hex"));
                i += 4;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

fn cases(file: &str) -> Vec<(String, Vec<u8>)> {
    let path = format!("{}/tests/vectors/{file}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("vector file");
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let (expected, input) = l.split_once('\t').expect("expected<TAB>input");
            (expected.to_string(), unescape(input))
        })
        .collect()
}

fn kind_name(k: ErrorKind) -> String {
    format!("err:{k:?}")
}

#[test]
fn test_vectors_http_date() {
    let all = cases("http_date.txt");
    assert!(all.len() >= 15);
    for (expected, input) in all {
        let got = match pn::http_date_at(&input, 1_792_540_800) {
            Ok(d) => d.unix().to_string(),
            Err(e) => kind_name(e.kind()),
        };
        assert_eq!(got, expected, "input {:?}", String::from_utf8_lossy(&input));
    }
}

#[test]
fn test_vectors_media_type() {
    let all = cases("media_type.txt");
    assert!(all.len() >= 15);
    for (expected, input) in all {
        let got = match pn::parse_media_type(&input) {
            Ok(m) => {
                let mut s = format!(
                    "{}/{}",
                    String::from_utf8_lossy(m.type_()).to_ascii_lowercase(),
                    String::from_utf8_lossy(m.subtype()).to_ascii_lowercase()
                );
                for p in m.params().iter() {
                    let mut buf = [0u8; 128];
                    let v = p.value.unescape_into(&mut buf).expect("fits");
                    s.push_str(&format!(
                        ";{}={}",
                        String::from_utf8_lossy(p.name).to_ascii_lowercase(),
                        String::from_utf8_lossy(v)
                    ));
                }
                s
            }
            Err(e) => kind_name(e.kind()),
        };
        assert_eq!(got, expected, "input {:?}", String::from_utf8_lossy(&input));
    }
}

#[test]
fn test_vectors_host() {
    let all = cases("host.txt");
    assert!(all.len() >= 15);
    for (expected, input) in all {
        let got = match pn::parse_host_port(&input) {
            Ok(hp) => {
                let mut s = match hp.host {
                    Host::Name(n) => format!("name:{}", String::from_utf8_lossy(n)),
                    Host::V4(a) => format!("v4:{a}"),
                    Host::V6(a) => format!("v6:{a}"),
                    Host::Future(f) => format!("future:{}", String::from_utf8_lossy(f)),
                };
                if let Some(p) = hp.port {
                    s.push_str(&format!("|{p}"));
                } else if hp.empty_port {
                    s.push_str("|empty");
                }
                s
            }
            Err(e) => kind_name(e.kind()),
        };
        assert_eq!(got, expected, "input {:?}", String::from_utf8_lossy(&input));
    }
}

#[test]
fn test_vectors_list() {
    let all = cases("list.txt");
    assert!(all.len() >= 10);
    for (expected, input) in all {
        let got = match pn::list(&input) {
            Ok(l) => l
                .iter()
                .map(|e| String::from_utf8_lossy(e).into_owned())
                .collect::<Vec<_>>()
                .join("|"),
            Err(e) => kind_name(e.kind()),
        };
        assert_eq!(got, expected, "input {:?}", String::from_utf8_lossy(&input));
    }
}

/// Escapes as the vector files do: `\t`, and `\xNN` for `\` and every byte
/// outside printable ASCII.
fn escape(v: &[u8]) -> String {
    v.iter()
        .map(|&b| match b {
            b'\t' => "\\t".to_string(),
            b'\\' => "\\x5c".to_string(),
            0x20..=0x7e => char::from(b).to_string(),
            _ => format!("\\x{b:02x}"),
        })
        .collect()
}

#[test]
fn test_vectors_content_disposition_tc2231() {
    let all = cases("content_disposition.txt");
    // Every tc2231 case, each with a recorded verdict.
    assert_eq!(all.len(), 87);
    for (expected, input) in all {
        let got = match pn::parse_content_disposition(&input) {
            Ok(d) => {
                let kind = match d.kind() {
                    pn::DispositionType::Inline => "inline".to_string(),
                    pn::DispositionType::Attachment => "attachment".to_string(),
                    pn::DispositionType::FormData => "form-data".to_string(),
                    pn::DispositionType::Other(o) => {
                        String::from_utf8_lossy(o).to_ascii_lowercase()
                    }
                    _ => "unknown".to_string(),
                };
                let mut buf = [0u8; 512];
                match d.filename() {
                    None => kind,
                    Some(f) => match f.decode_into(&mut buf) {
                        Ok(s) => format!("{kind};filename={}", escape(s.as_bytes())),
                        Err(e) => format!("{kind};filename={}", kind_name(e.kind())),
                    },
                }
            }
            Err(e) => kind_name(e.kind()),
        };
        assert_eq!(got, expected, "input {:?}", String::from_utf8_lossy(&input));
    }
}
