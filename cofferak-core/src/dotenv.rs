//! `.env` file parsing and writing, for `cofferak import-env`,
//! `export-env` and `run`.
//!
//! Parsing follows the common dotenv conventions (the `dotenv` family of
//! libraries and Docker Compose's `env_file`):
//!
//! - blank lines and lines starting with `#` are ignored;
//! - an optional leading `export ` is accepted;
//! - `KEY=VALUE`, with optional spaces around `=`;
//! - unquoted values end at an inline comment (` #` preceded by
//!   whitespace) and are trimmed;
//! - `'single quoted'` values are literal and may span lines;
//! - `"double quoted"` values may span lines and understand `\n`, `\r`,
//!   `\t`, `\"`, `\\` and `\$`;
//! - variable references like `${OTHER}` are **not** expanded: values are
//!   stored exactly as written, so nothing changes meaning on import.
//!
//! Keys must be valid environment variable names (`[A-Za-z_][A-Za-z0-9_]*`);
//! anything else is reported with its line number instead of guessed at.
//! [`format`] writes values back double-quoted with every special
//! character escaped, so `parse(format(x)) == x` for any text value.

use std::fmt;

/// One `KEY=value` pair from a `.env` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    pub key: String,
    pub value: String,
    /// 1-based line where the entry starts.
    pub line: usize,
}

/// A `.env` syntax error, with the 1-based line it occurred on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// True if `name` is a valid environment variable name.
pub fn is_valid_key(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// Parse the contents of a `.env` file. Later duplicates of a key replace
/// earlier ones (as dotenv loaders do), the returned list keeps the order
/// of each key's last occurrence.
pub fn parse(input: &str) -> Result<Vec<EnvVar>, ParseError> {
    let input = input.strip_prefix('\u{feff}').unwrap_or(input);
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    let mut line = 1;
    let mut out: Vec<EnvVar> = Vec::new();

    let err = |line: usize, m: &str| ParseError {
        line,
        message: m.to_string(),
    };

    while i < chars.len() {
        // Skip leading whitespace (not newlines) on the line.
        while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        // Blank line, CRLF, or comment line.
        if chars[i] == '\n' || chars[i] == '\r' || chars[i] == '#' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            if i < chars.len() {
                i += 1;
                line += 1;
            }
            continue;
        }

        let start_line = line;
        // Key (optionally preceded by `export `).
        let mut key = String::new();
        while i < chars.len() && !matches!(chars[i], '=' | ' ' | '\t' | '\n' | '\r') {
            key.push(chars[i]);
            i += 1;
        }
        if key == "export" && i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
            while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
                i += 1;
            }
            key.clear();
            while i < chars.len() && !matches!(chars[i], '=' | ' ' | '\t' | '\n' | '\r') {
                key.push(chars[i]);
                i += 1;
            }
        }
        while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            return Err(err(
                start_line,
                &format!("expected KEY=VALUE, found {key:?} without '='"),
            ));
        }
        if !is_valid_key(&key) {
            return Err(err(
                start_line,
                &format!("{key:?} is not a valid variable name (use letters, digits and _, not starting with a digit)"),
            ));
        }
        i += 1; // '='
        while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
            i += 1;
        }

        let mut value = String::new();
        if i < chars.len() && (chars[i] == '\'' || chars[i] == '"') {
            let quote = chars[i];
            i += 1;
            let mut closed = false;
            while i < chars.len() {
                let c = chars[i];
                if c == quote {
                    closed = true;
                    i += 1;
                    break;
                }
                if c == '\n' {
                    line += 1;
                }
                if quote == '"' && c == '\\' && i + 1 < chars.len() {
                    let n = chars[i + 1];
                    let esc = match n {
                        'n' => Some('\n'),
                        'r' => Some('\r'),
                        't' => Some('\t'),
                        '"' => Some('"'),
                        '\\' => Some('\\'),
                        '$' => Some('$'),
                        '`' => Some('`'),
                        _ => None,
                    };
                    if let Some(e) = esc {
                        value.push(e);
                        i += 2;
                        continue;
                    }
                }
                value.push(c);
                i += 1;
            }
            if !closed {
                return Err(err(
                    start_line,
                    &format!("unterminated {quote} quote for {key}"),
                ));
            }
            // After the closing quote: only whitespace or a comment.
            while i < chars.len() && (chars[i] == ' ' || chars[i] == '\t') {
                i += 1;
            }
            if i < chars.len() && !matches!(chars[i], '#' | '\n' | '\r') {
                return Err(err(
                    line,
                    &format!("unexpected text after the closing quote of {key}"),
                ));
            }
        } else {
            while i < chars.len() && chars[i] != '\n' && chars[i] != '\r' {
                if chars[i] == '#' && value.ends_with([' ', '\t']) {
                    break;
                }
                value.push(chars[i]);
                i += 1;
            }
            let trimmed = value.trim_end().to_string();
            value = trimmed;
        }
        // Consume the rest of the line (comment, CR) and the newline.
        while i < chars.len() && chars[i] != '\n' {
            i += 1;
        }
        if i < chars.len() {
            i += 1;
            line += 1;
        }

        out.retain(|v| v.key != key);
        out.push(EnvVar {
            key,
            value,
            line: start_line,
        });
    }
    Ok(out)
}

/// Quote `value` for a `.env` file: always double-quoted, with `\`, `"`,
/// `$`, newline, carriage return and tab escaped.
pub fn quote(value: &str) -> String {
    let mut s = String::with_capacity(value.len() + 2);
    s.push('"');
    for c in value.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '$' => s.push_str("\\$"),
            '`' => s.push_str("\\`"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

/// Write `vars` as `.env` text, one `KEY="value"` per line.
pub fn format<'a>(vars: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut out = String::new();
    for (k, v) in vars {
        out.push_str(k);
        out.push('=');
        out.push_str(&quote(v));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kv(input: &str) -> Vec<(String, String)> {
        parse(input)
            .unwrap()
            .into_iter()
            .map(|v| (v.key, v.value))
            .collect()
    }

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parses_the_usual_shapes() {
        let input = "\
# database
DB_HOST=localhost
export API_KEY=abc=123
PORT = 8080   # dev only
EMPTY=
SPACED=  hello world
HASH_IN_VALUE=abc#def
";
        assert_eq!(
            kv(input),
            pairs(&[
                ("DB_HOST", "localhost"),
                ("API_KEY", "abc=123"),
                ("PORT", "8080"),
                ("EMPTY", ""),
                ("SPACED", "hello world"),
                ("HASH_IN_VALUE", "abc#def"),
            ])
        );
    }

    #[test]
    fn quoted_values() {
        let input = r#"
SINGLE='p@ss $word # not a comment'
DOUBLE="line1\nline2\t\"quoted\" \$HOME \\ back"
COMMENT_AFTER="value" # trailing comment
UNKNOWN_ESCAPE="keep \q as is"
"#;
        assert_eq!(
            kv(input),
            pairs(&[
                ("SINGLE", "p@ss $word # not a comment"),
                ("DOUBLE", "line1\nline2\t\"quoted\" $HOME \\ back"),
                ("COMMENT_AFTER", "value"),
                ("UNKNOWN_ESCAPE", "keep \\q as is"),
            ])
        );
    }

    #[test]
    fn multi_line_quoted_values_like_pem_keys() {
        let input =
            "KEY=\"-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----\"\nNEXT=1\n";
        let vars = parse(input).unwrap();
        assert_eq!(
            vars[0].value,
            "-----BEGIN PRIVATE KEY-----\nMIIabc\n-----END PRIVATE KEY-----"
        );
        assert_eq!((vars[1].key.as_str(), vars[1].line), ("NEXT", 4));
    }

    #[test]
    fn crlf_bom_and_duplicates() {
        let input = "\u{feff}A=1\r\nB='two'\r\nA=3\r\n";
        assert_eq!(kv(input), pairs(&[("B", "two"), ("A", "3")]));
    }

    #[test]
    fn variable_references_are_not_expanded() {
        assert_eq!(kv("URL=${HOST}:5432\n"), pairs(&[("URL", "${HOST}:5432")]));
    }

    #[test]
    fn errors_name_the_line() {
        let e = parse("A=1\nnot a pair\n").unwrap_err();
        assert_eq!(e.line, 2);
        let e = parse("A=1\n1BAD=x\n").unwrap_err();
        assert_eq!(e.line, 2);
        assert!(e.message.contains("not a valid variable name"));
        let e = parse("A=\"open\nB=2\n").unwrap_err();
        assert_eq!(e.line, 1);
        assert!(e.message.contains("unterminated"));
        let e = parse("A=\"x\" junk\n").unwrap_err();
        assert!(e.message.contains("after the closing quote"));
    }

    #[test]
    fn format_then_parse_round_trips_any_text() {
        let samples = [
            "",
            "plain",
            "with spaces and = signs",
            "quotes \" and ' and `backticks`",
            "dollar $HOME ${X} and \\ backslash",
            "backtick `rm -rf /` and $(id)",
            "multi\nline\r\nvalue\twith tab",
            "# looks like a comment",
            "unicode ünïcødé 🔐",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----\n",
        ];
        let vars: Vec<(String, &str)> = samples
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("K{i}"), *v))
            .collect();
        let text = format(vars.iter().map(|(k, v)| (k.as_str(), *v)));
        let parsed = parse(&text).unwrap();
        assert_eq!(parsed.len(), samples.len());
        for (p, s) in parsed.iter().zip(samples) {
            assert_eq!(p.value, s, "round trip failed for {s:?}");
        }
    }

    #[test]
    fn key_validation() {
        for ok in ["A", "_x", "DB_HOST", "a1"] {
            assert!(is_valid_key(ok), "{ok}");
        }
        for bad in ["", "1A", "A-B", "A.B", "A B", "ÄB"] {
            assert!(!is_valid_key(bad), "{bad}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn sourcing_the_output_in_a_shell_never_runs_commands() {
        let marker = std::env::temp_dir().join(format!("cfk-dotenv-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let value = format!(
            "`touch {m}` $(touch {m}) ${{X}} \\ \"",
            m = marker.display()
        );
        let file = format([("V", value.as_str())]);
        assert!(quote("`x`").contains("\\`"));
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("{file}\nprintf %s \"$V\""))
            .output()
            .unwrap();
        assert!(!marker.exists(), "a command in the value was executed");
        assert_eq!(String::from_utf8(out.stdout).unwrap(), value);
    }
}
