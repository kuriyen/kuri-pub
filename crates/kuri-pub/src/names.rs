//! Kinds, channels, names, versions and paths, and the rules they follow.
//!
//! A name, a version and every segment of a path may become a file or
//! directory name on a front end's machine, Windows included. So they follow
//! one rule, the segment rule, strict enough for every filesystem a front end
//! is likely to write to. Loosening a rule later is an addition; tightening it
//! would break manifests already published.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use unicode_normalization::is_nfc;

use crate::fault::{Code, Fault};

/// Longest name, in bytes of UTF-8.
pub const MAX_NAME: usize = 128;
/// Longest version, in bytes of UTF-8.
pub const MAX_VERSION: usize = 64;
/// Longest path in a manifest, in bytes of UTF-8.
pub const MAX_PATH: usize = 1024;
/// Longest segment of a kind or a channel.
pub const MAX_LABEL: usize = 64;

/// Characters Windows refuses in a file name, besides control characters.
/// `/` separates a path's segments, so it is refused inside one too.
const FORBIDDEN: [char; 9] = ['/', '\\', ':', '<', '>', '"', '|', '?', '*'];

/// Names Windows keeps for devices, whatever the extension: `nul.txt` opens
/// the null device. The superscript digits are reserved as well.
const RESERVED: [&str; 28] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "COM¹", "COM²", "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
    "LPT9", "LPT¹", "LPT²", "LPT³",
];

/// Checks the segment rule; on failure, says why.
pub fn check_segment(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("is empty".into());
    }
    // Two spellings of one visible name must not be two names. Refused rather
    // than normalized, so what is stored is what the publisher sent.
    if !is_nfc(s) {
        return Err("is not in Unicode NFC".into());
    }
    if let Some(c) = s.chars().find(|c| c.is_control()) {
        return Err(format!("contains the control character {c:?}"));
    }
    if let Some(c) = s.chars().find(|c| FORBIDDEN.contains(c)) {
        return Err(format!("contains {c:?}"));
    }
    // Windows drops a trailing dot or space, so `a.` and `a` are one file;
    // this also refuses `.` and `..`.
    if s.ends_with(['.', ' ']) {
        return Err("ends in a dot or a space".into());
    }
    let stem = s.split('.').next().unwrap_or(s).trim_end_matches(' ');
    if RESERVED.iter().any(|r| stem.eq_ignore_ascii_case(r)) {
        return Err(format!("{stem:?} is a device name on Windows"));
    }
    Ok(())
}

/// `[a-z0-9][a-z0-9-]{0,63}`.
fn is_label(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_LABEL
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

fn bad_name(what: &str, s: &str, why: impl fmt::Display) -> Fault {
    Fault::new(Code::BadName, format!("{what} {s:?} {why}"))
}

macro_rules! text_newtype {
    ($(#[$doc:meta])* $ty:ident, $check:expr) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $ty(String);

        impl $ty {
            /// Checks `s` against the rule; a refusal is `bad_name`.
            pub fn new(s: impl Into<String>) -> Result<Self, Fault> {
                let s = s.into();
                let check: fn(&str) -> Result<(), Fault> = $check;
                check(&s)?;
                Ok($ty(s))
            }

            /// The text, as checked.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $ty {
            type Error = Fault;
            fn try_from(s: String) -> Result<Self, Fault> {
                $ty::new(s)
            }
        }

        impl From<$ty> for String {
            fn from(v: $ty) -> String {
                v.0
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

text_newtype!(
    /// What a thing is: `app`, `mod`, or a qualified kind such as `mod.bg3`,
    /// where the qualifier keeps two games' mods of one name apart. One label
    /// `[a-z0-9][a-z0-9-]{0,63}`, optionally `.` and a second one. The depot
    /// keeps no list of kinds.
    Kind,
    |s| {
        let ok = match s.split_once('.') {
            None => is_label(s),
            Some((head, tail)) => is_label(head) && is_label(tail),
        };
        if ok {
            Ok(())
        } else {
            Err(bad_name("kind", s, "is not a label, or two joined by a dot"))
        }
    }
);

text_newtype!(
    /// A movable pointer to a version, such as `stable`: one label.
    Channel,
    |s| {
        if is_label(s) {
            Ok(())
        } else {
            Err(bad_name("channel", s, "is not a label"))
        }
    }
);

text_newtype!(
    /// A thing's name, unique within its kind: the segment rule, at most
    /// [`MAX_NAME`] bytes.
    Name,
    |s| {
        if s.len() > MAX_NAME {
            return Err(bad_name("name", s, format!("is over {MAX_NAME} bytes")));
        }
        check_segment(s).map_err(|why| bad_name("name", s, why))
    }
);

text_newtype!(
    /// A version, opaque: the depot never orders versions. The segment rule,
    /// at most [`MAX_VERSION`] bytes.
    Version,
    |s| {
        if s.len() > MAX_VERSION {
            return Err(bad_name("version", s, format!("is over {MAX_VERSION} bytes")));
        }
        check_segment(s).map_err(|why| bad_name("version", s, why))
    }
);

/// Checks one path of a manifest: relative, `/`-separated, every segment by
/// the segment rule, at most [`MAX_PATH`] bytes.
pub fn check_path(path: &str) -> Result<(), String> {
    if path.len() > MAX_PATH {
        return Err(format!("path {path:?} is over {MAX_PATH} bytes"));
    }
    // An empty segment catches a leading `/`, a trailing one and `//`.
    for segment in path.split('/') {
        check_segment(segment)
            .map_err(|why| format!("path {path:?}: segment {segment:?} {why}"))?;
    }
    Ok(())
}

/// Checks that a manifest's paths can all exist at once on a filesystem that
/// ignores case: no two equal after lowercasing, and none a directory of
/// another (`a` with `A/b`).
pub fn check_paths_together<'a>(paths: impl IntoIterator<Item = &'a str>) -> Result<(), String> {
    let folded: Vec<(String, &str)> = paths.into_iter().map(|p| (p.to_lowercase(), p)).collect();
    let mut seen = HashSet::new();
    for (key, path) in &folded {
        if !seen.insert(key.as_str()) {
            return Err(format!(
                "path {path:?} differs from another only in case, or not at all"
            ));
        }
    }
    for (key, path) in &folded {
        for (i, _) in key.match_indices('/') {
            if seen.contains(&key[..i]) {
                return Err(format!(
                    "path {path:?} lies under another path that is a file"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn refused(s: &str) -> String {
        check_segment(s).expect_err(s)
    }

    #[test]
    fn ordinary_segments_pass() {
        for s in [
            "a", "Mod Name", "v1.2.3", "été", "大地", "a-b_c", ".hidden", "con-fig", "comet",
            "nul_",
        ] {
            check_segment(s).unwrap_or_else(|e| panic!("{s:?} {e}"));
        }
    }

    #[test]
    fn empty_is_refused() {
        assert!(refused("").contains("empty"));
    }

    #[test]
    fn decomposed_text_is_refused() {
        // "é" as `e` + combining acute: the NFD spelling.
        assert!(refused("e\u{301}te").contains("NFC"));
    }

    #[test]
    fn control_characters_are_refused() {
        for s in ["a\0b", "a\tb", "a\u{7f}", "a\u{85}"] {
            assert!(refused(s).contains("control"), "{s:?}");
        }
    }

    #[test]
    fn windows_forbidden_characters_are_refused() {
        for c in FORBIDDEN {
            let s = format!("a{c}b");
            assert!(refused(&s).contains("contains"), "{s:?}");
        }
        // `\` is a separator on Windows: this would climb out of the folder.
        assert!(refused(r"a\..\..\b").contains("'\\\\'"));
        assert!(refused("C:evil").contains("':'"));
    }

    #[test]
    fn trailing_dot_or_space_is_refused() {
        for s in [".", "..", "a.", "a "] {
            assert!(refused(s).contains("ends in"), "{s:?}");
        }
    }

    #[test]
    fn device_names_are_refused_in_any_case_and_with_any_extension() {
        for s in [
            "CON",
            "con",
            "Nul.txt",
            "aux.tar.gz",
            "COM1",
            "lpt9.log",
            "COM¹",
            "con .txt",
        ] {
            assert!(refused(s).contains("device"), "{s:?}");
        }
    }

    #[test]
    fn kinds() {
        for s in ["app", "mod", "mod.bg3", "a", "0-x.y-1", &"a".repeat(64)] {
            Kind::new(s).unwrap_or_else(|e| panic!("{s:?} {e}"));
        }
        for s in [
            "",
            "App",
            "-a",
            "a_b",
            "mod.",
            ".mod",
            "mod.bg3.x",
            "mod..x",
            "a b",
            &"a".repeat(65),
        ] {
            assert_eq!(Kind::new(s).expect_err(s).code, Code::BadName, "{s:?}");
        }
    }

    #[test]
    fn a_channel_is_one_label() {
        Channel::new("stable").unwrap();
        Channel::new("stable.x").unwrap_err();
        Channel::new("Stable").unwrap_err();
    }

    #[test]
    fn names_and_versions_have_length_limits() {
        Name::new("n".repeat(MAX_NAME)).unwrap();
        Name::new("n".repeat(MAX_NAME + 1)).unwrap_err();
        Version::new("1".repeat(MAX_VERSION)).unwrap();
        Version::new("1".repeat(MAX_VERSION + 1)).unwrap_err();
    }

    #[test]
    fn names_and_versions_follow_the_segment_rule() {
        for s in ["", "a/b", "CON", "a.", "e\u{301}"] {
            assert_eq!(Name::new(s).expect_err(s).code, Code::BadName);
            assert_eq!(Version::new(s).expect_err(s).code, Code::BadName);
        }
    }

    #[test]
    fn paths() {
        check_path("a").unwrap();
        check_path("dir/sub/file.pak").unwrap();
        for p in ["/a", "a/", "a//b", "a/../b", "./a", r"a\b", "a/CON/b"] {
            check_path(p).expect_err(p);
        }
        let long = format!("{}/x", "a".repeat(MAX_PATH - 2));
        check_path(&long).unwrap();
        check_path(&format!("a{long}")).expect_err("too long");
    }

    #[test]
    fn paths_must_differ_after_lowercasing() {
        check_paths_together(["a", "b", "dir/a"]).unwrap();
        check_paths_together(["a", "a"]).unwrap_err();
        check_paths_together(["Readme", "README"]).unwrap_err();
        check_paths_together(["Été", "été"]).unwrap_err();
    }

    #[test]
    fn a_file_cannot_also_be_a_directory() {
        check_paths_together(["ab", "a/b"]).unwrap();
        let err = check_paths_together(["data", "Data/x.bin"]).unwrap_err();
        assert!(err.contains("under another path"), "{err}");
        check_paths_together(["a/b", "a/b/c"]).unwrap_err();
    }

    #[test]
    fn deserializing_checks_the_rule() {
        let v = ciborium::Value::Text("Bad Kind".into());
        let err = v.deserialized::<Kind>().unwrap_err().to_string();
        assert!(err.contains("bad_name"), "{err}");
    }
}
