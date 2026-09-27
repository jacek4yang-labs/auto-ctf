//! Challenge-parameter extraction from raw text files.
//!
//! Ported from the reference Python drivers (`refs/oracle/solve_dasbook_ch06.py`,
//! `refs/oracle/bulk_solve_crypto.py` — see docs/DEPS.md provenance) as a
//! reusable primitive: given arbitrary challenge attachment text, pull out the
//! known numeric parameter keys in whatever assignment shape appears
//! (`k:v`, `k=v`, quoted, python tuple literals, hex).

use std::collections::BTreeMap;

/// Canonical parameter key for a raw key found in a file (case-insensitive,
/// aliases like `N`/`C` collapse onto `n`/`c`; numbered broadcast keys
/// `n1..n99`/`c1..c99`/`e1..e99` pass through lowercased). Returns None for
/// unknown keys.
pub fn canonical_key(raw: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();
    let is_numbered = lower.len() >= 2
        && matches!(lower.as_bytes()[0], b'n' | b'c' | b'e')
        && lower.as_bytes()[1..].iter().all(|b| b.is_ascii_digit());
    if is_numbered {
        return Some(lower);
    }
    canonical_static(&lower).map(|s| s.to_string())
}

fn canonical_static(lower: &str) -> Option<&'static str> {
    match lower {
        "n" => Some("n"),
        "e" => Some("e"),
        "c" => Some("c"),
        "d" => Some("d"),
        "p" => Some("p"),
        "q" => Some("q"),
        "dp" => Some("dp"),
        "dq" => Some("dq"),
        "e1" => Some("e1"),
        "e2" => Some("e2"),
        "c1" => Some("c1"),
        "c2" => Some("c2"),
        "sum_a" | "a" => Some("sum_a"),
        "sum_b" | "b" => Some("sum_b"),
        _ => None,
    }
}

/// Extract canonical numeric parameters from text. Decimal or 0x-hex values.
/// First occurrence wins (challenge files sometimes repeat keys in comments).
pub fn extract_numeric_params(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // python tuple literal shape: ('c=', '0x...')
        let line = line
            .trim_start_matches('(')
            .trim_end_matches(')')
            .trim()
            .trim_start_matches('\'')
            .trim_start_matches('"');
        let Some((raw_key, raw_val)) = split_assign(line) else { continue };
        let Some(key) = canonical_key(raw_key) else { continue };
        let val = raw_val
            .trim_matches(|c| c == ',' || c == '\'' || c == '"' || c == ' ' || c == '(')
            .trim();
        if val.is_empty() || !is_number(val) {
            continue;
        }
        out.entry(key).or_insert_with(|| val.to_string());
    }
    out
}

fn split_assign(line: &str) -> Option<(&str, &str)> {
    for sep in [": ", ":", "=", " = "] {
        if let Some(pos) = line.find(sep) {
            let k = line[..pos].trim();
            let v = &line[pos + sep.len()..];
            if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Some((k, v));
            }
        }
    }
    None
}

fn is_number(v: &str) -> bool {
    let t = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")).unwrap_or(v);
    !t.is_empty() && t.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse a BigUint from dec or 0x-hex.
pub fn parse_biguint(s: &str) -> Result<num_bigint::BigUint, String> {
    use num_traits::Num;
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        num_bigint::BigUint::from_str_radix(h, 16).map_err(|e| e.to_string())
    } else {
        num_bigint::BigUint::from_str_radix(t, 10).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colon_and_equals_forms() {
        let t = "p:123\ne: 65537\nq:456\nc: 0x10\n";
        let m = extract_numeric_params(t);
        assert_eq!(m["p"], "123");
        assert_eq!(m["e"], "65537");
        assert_eq!(m["q"], "456");
        assert_eq!(m["c"], "0x10");
    }

    #[test]
    fn parses_python_tuple_and_aliases() {
        let t = "('c=', '0x7a7e')\n('e=', '0x872a335')\nN: 999\n";
        let m = extract_numeric_params(t);
        assert_eq!(m["c"], "0x7a7e");
        assert_eq!(m["e"], "0x872a335");
        assert_eq!(m["n"], "999"); // N aliased to n
    }

    #[test]
    fn skips_comments_and_non_numeric() {
        let t = "# p = 123\ndp = not_a_number\nimport os\nx: 1\n";
        let m = extract_numeric_params(t);
        assert!(m.get("p").is_none());
        assert!(m.get("dp").is_none());
        assert!(m.get("x").is_none());
    }

    #[test]
    fn first_occurrence_wins() {
        let t = "n: 1\nn: 2\n";
        assert_eq!(extract_numeric_params(t)["n"], "1");
    }
}
