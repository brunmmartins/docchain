//! The subset of ECMA-262 regular expressions that schema `pattern` keywords may use.
//!
//! Supported: an optional leading `^`, an optional trailing unescaped `$`, literal characters,
//! the escaped characters `\ ^ $ . | ? * + ( ) [ ] { } /`, `\d` (ASCII `[0-9]`), non-negated
//! character classes, and the quantifiers `?`, `*`, `+`, `{n}`, `{n,}`, and `{n,m}`. Anything else
//! makes the schema unsupported, so validation fails closed: groups, alternation, `.`, `^` or
//! `$` anywhere else, lookaround, backreferences, negated classes, lazy or stacked quantifiers,
//! other escapes, `\-` outside a class, empty classes, and characters outside the Basic
//! Multilingual Plane.
//!
//! A class holds literals, the escaped characters above, `\-`, `\d`, and ascending ranges. It is
//! read left to right, as ECMA-262 parses it: a member followed by `-` and then by anything other
//! than `]` is the low bound of a range, and the next member is its high bound. Reading starts
//! afresh after a range, so a `-` right after one is a member. Each bound is one character and
//! never `\d`: `\d` as either operand of a range is refused, while `[\d-]`, `[-\d]`, and
//! `[a-z-\d]` hold no such range and compile. No range may include any value from U+D800 to
//! U+DFFF.
//!
//! Every admitted pattern is therefore a valid ECMA-262 pattern both with the `u` flag and
//! without it, in the main grammar and under Annex B: each escaped character is a syntax
//! character or `/`, `\-` appears only inside a class, and no range takes `\d` as an operand.
//!
//! Every atom matches exactly one character, so matching is a linear pass per atom over the set
//! of reachable positions, with no backtracking. Every atom matches only Basic Multilingual Plane
//! characters outside U+D800 to U+DFFF, so none can match a UTF-16 surrogate code unit or any
//! part of a character outside that plane. For any string without lone surrogates, matching per
//! Unicode scalar therefore gives the same answer as ECMA-262 matching with the `u` flag, which
//! reads code points, and without it, which reads UTF-16 code units. No other flag is claimed.

use crate::DomainError;

const MAX_PATTERN_CHARS: usize = 256;
const MAX_REPEAT: usize = 1_000;

#[derive(Clone, Debug)]
pub(crate) struct Pattern {
    anchored_start: bool,
    anchored_end: bool,
    atoms: Vec<Atom>,
}

#[derive(Clone, Debug)]
struct Atom {
    ranges: Vec<(char, char)>,
    min: usize,
    max: Option<usize>,
}

impl Atom {
    fn matches(&self, character: char) -> bool {
        self.ranges
            .iter()
            .any(|(low, high)| (*low..=*high).contains(&character))
    }
}

impl Pattern {
    /// Compiles `source`, or reports it unsupported.
    pub(crate) fn compile(source: &str) -> Result<Self, DomainError> {
        let characters = source.chars().collect::<Vec<_>>();
        if characters.len() > MAX_PATTERN_CHARS
            || characters
                .iter()
                .any(|character| u32::from(*character) > 0xFFFF)
        {
            return Err(DomainError::UnsupportedSchema);
        }
        let mut index = 0;
        let anchored_start = characters.first() == Some(&'^');
        if anchored_start {
            index = 1;
        }
        let mut end = characters.len();
        let anchored_end =
            end > index && characters[end - 1] == '$' && !is_escaped(&characters, end - 1);
        if anchored_end {
            end -= 1;
        }
        let mut atoms = Vec::new();
        while index < end {
            let (ranges, next) = parse_atom(&characters[..end], index)?;
            let (min, max, next) = parse_quantifier(&characters[..end], next)?;
            atoms.push(Atom { ranges, min, max });
            index = next;
        }
        Ok(Self {
            anchored_start,
            anchored_end,
            atoms,
        })
    }

    /// Reports whether the pattern matches anywhere in `input`, as JSON Schema requires.
    pub(crate) fn is_match(&self, input: &str) -> bool {
        let characters = input.chars().collect::<Vec<_>>();
        let length = characters.len();
        let mut reachable = vec![!self.anchored_start; length + 1];
        reachable[0] = true;
        for atom in &self.atoms {
            reachable = advance(&reachable, &characters, atom);
        }
        if self.anchored_end {
            reachable[length]
        } else {
            reachable.iter().any(|position| *position)
        }
    }
}

/// Positions reachable after `atom`, given positions reachable before it.
///
/// Position `q` is reachable when some reachable `p` has `min <= q - p <= max` and every
/// character in `p..q` matches. `run[q]` counts the matching characters ending at `q`, and a
/// prefix sum over `reachable` answers each window query in constant time.
fn advance(reachable: &[bool], characters: &[char], atom: &Atom) -> Vec<bool> {
    let length = characters.len();
    let mut prefix = vec![0_usize; length + 2];
    for (position, is_reachable) in reachable.iter().enumerate() {
        prefix[position + 1] = prefix[position] + usize::from(*is_reachable);
    }
    let mut next = vec![false; length + 1];
    let mut run = 0_usize;
    for (position, slot) in next.iter_mut().enumerate() {
        if position > 0 {
            run = if atom.matches(characters[position - 1]) {
                run + 1
            } else {
                0
            };
        }
        if position < atom.min {
            continue;
        }
        let highest = position - atom.min;
        let lowest_by_run = position - run.min(position);
        let lowest = atom.max.map_or(lowest_by_run, |max| {
            lowest_by_run.max(position.saturating_sub(max))
        });
        if lowest <= highest && prefix[highest + 1] > prefix[lowest] {
            *slot = true;
        }
    }
    next
}

fn is_escaped(characters: &[char], index: usize) -> bool {
    let backslashes = characters[..index]
        .iter()
        .rev()
        .take_while(|character| **character == '\\')
        .count();
    backslashes % 2 == 1
}

/// Characters that may follow a backslash anywhere: the syntax characters and `/`.
const ESCAPABLE: &[char] = &[
    '\\', '^', '$', '.', '|', '?', '*', '+', '(', ')', '[', ']', '{', '}', '/',
];

/// The lowest and highest surrogate code points, which no class range may include.
const SURROGATES: (u32, u32) = (0xD800, 0xDFFF);

fn parse_atom(
    characters: &[char],
    index: usize,
) -> Result<(Vec<(char, char)>, usize), DomainError> {
    match characters[index] {
        '\\' => {
            let escaped = *characters
                .get(index + 1)
                .ok_or(DomainError::UnsupportedSchema)?;
            if escaped == 'd' {
                Ok((vec![('0', '9')], index + 2))
            } else if ESCAPABLE.contains(&escaped) {
                Ok((vec![(escaped, escaped)], index + 2))
            } else {
                Err(DomainError::UnsupportedSchema)
            }
        }
        '[' => parse_class(characters, index + 1),
        '^' | '$' | '.' | '|' | '?' | '*' | '+' | '(' | ')' | ']' | '{' | '}' => {
            Err(DomainError::UnsupportedSchema)
        }
        literal => Ok((vec![(literal, literal)], index + 1)),
    }
}

fn parse_class(
    characters: &[char],
    mut index: usize,
) -> Result<(Vec<(char, char)>, usize), DomainError> {
    if characters.get(index) == Some(&'^') {
        return Err(DomainError::UnsupportedSchema);
    }
    let mut ranges = Vec::new();
    loop {
        let character = *characters
            .get(index)
            .ok_or(DomainError::UnsupportedSchema)?;
        if character == ']' {
            if ranges.is_empty() {
                return Err(DomainError::UnsupportedSchema);
            }
            return Ok((ranges, index + 1));
        }
        let (low, next) = class_member(characters, index)?;
        let starts_range =
            characters.get(next) == Some(&'-') && characters.get(next + 1) != Some(&']');
        if low == ClassMember::Digit {
            // `\d` cannot be a range bound; ECMA-262 makes that an early error.
            if starts_range {
                return Err(DomainError::UnsupportedSchema);
            }
            ranges.push(('0', '9'));
            index = next;
            continue;
        }
        let ClassMember::Char(low) = low else {
            return Err(DomainError::UnsupportedSchema);
        };
        if starts_range {
            let (high, after) = class_member(characters, next + 1)?;
            let ClassMember::Char(high) = high else {
                return Err(DomainError::UnsupportedSchema);
            };
            if low > high || (u32::from(low) <= SURROGATES.1 && u32::from(high) >= SURROGATES.0) {
                return Err(DomainError::UnsupportedSchema);
            }
            ranges.push((low, high));
            index = after;
        } else {
            ranges.push((low, low));
            index = next;
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClassMember {
    Char(char),
    Digit,
}

fn class_member(characters: &[char], index: usize) -> Result<(ClassMember, usize), DomainError> {
    match *characters
        .get(index)
        .ok_or(DomainError::UnsupportedSchema)?
    {
        '\\' => match characters.get(index + 1) {
            Some('d') => Ok((ClassMember::Digit, index + 2)),
            // `\-` is a class escape under the `u` flag, so it is admitted only here.
            Some(escaped) if *escaped == '-' || ESCAPABLE.contains(escaped) => {
                Ok((ClassMember::Char(*escaped), index + 2))
            }
            _ => Err(DomainError::UnsupportedSchema),
        },
        // An unescaped anchor character is outside the subset even where ECMA-262 reads a literal.
        '[' | ']' | '^' | '$' => Err(DomainError::UnsupportedSchema),
        literal => Ok((ClassMember::Char(literal), index + 1)),
    }
}

fn parse_quantifier(
    characters: &[char],
    index: usize,
) -> Result<(usize, Option<usize>, usize), DomainError> {
    let (min, max, next) = match characters.get(index) {
        Some('?') => (0, Some(1), index + 1),
        Some('*') => (0, None, index + 1),
        Some('+') => (1, None, index + 1),
        Some('{') => {
            let close = characters[index..]
                .iter()
                .position(|character| *character == '}')
                .map(|offset| index + offset)
                .ok_or(DomainError::UnsupportedSchema)?;
            let body = characters[index + 1..close].iter().collect::<String>();
            let (min, max) = match body.split_once(',') {
                None => {
                    let exact = repeat_count(&body)?;
                    (exact, Some(exact))
                }
                Some((min, "")) => (repeat_count(min)?, None),
                Some((min, max)) => (repeat_count(min)?, Some(repeat_count(max)?)),
            };
            if max.is_some_and(|max| max < min) {
                return Err(DomainError::UnsupportedSchema);
            }
            (min, max, close + 1)
        }
        _ => return Ok((1, Some(1), index)),
    };
    if matches!(characters.get(next), Some('?' | '*' | '+' | '{')) {
        return Err(DomainError::UnsupportedSchema);
    }
    Ok((min, max, next))
}

fn repeat_count(digits: &str) -> Result<usize, DomainError> {
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) || digits.len() > 4 {
        return Err(DomainError::UnsupportedSchema);
    }
    digits
        .parse::<usize>()
        .ok()
        .filter(|count| *count <= MAX_REPEAT)
        .ok_or(DomainError::UnsupportedSchema)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::Pattern;

    fn matches(pattern: &str, input: &str) -> bool {
        Pattern::compile(pattern)
            .expect("supported")
            .is_match(input)
    }

    #[test]
    fn anchored_reference_pattern_bounds_its_repeat() {
        let pattern = "^SYN-[A-Z0-9]{6,24}$";
        assert!(matches(pattern, "SYN-APP001"));
        assert!(matches(pattern, "SYN-ABCDEF"));
        assert!(matches(pattern, &format!("SYN-{}", "A".repeat(24))));
        assert!(!matches(pattern, "SYN-ABCDE"));
        assert!(!matches(pattern, &format!("SYN-{}", "A".repeat(25))));
        assert!(!matches(pattern, "SYN-abcdef"));
        assert!(!matches(pattern, "xSYN-ABCDEF"));
        assert!(!matches(pattern, "SYN-ABCDEFx"));
    }

    #[test]
    fn unanchored_patterns_search_anywhere() {
        assert!(matches("b+c", "aaabbbcddd"));
        assert!(!matches("b+c", "aaabbbddd"));
        assert!(matches("^a?b*$", ""));
        assert!(matches("x{2,}", "axxxb"));
        assert!(!matches("x{2,}", "axb"));
        assert!(matches(r"^\d{3}-[a\-z]$", "123--"));
    }

    #[test]
    fn unsupported_constructs_fail_closed() {
        let too_long = "a".repeat(257);
        let accepted = [
            ("(a)", "group"),
            ("(?:a)", "non-capturing group"),
            ("a|b", "alternation"),
            ("a.", "any character"),
            ("a^", "caret after the start"),
            ("^^a", "second caret"),
            ("a$b", "dollar before the end"),
            ("a$$", "second dollar"),
            ("[a^]", "caret inside a class"),
            ("[a$]", "dollar inside a class"),
            ("(?=a)", "lookahead"),
            ("(?!a)", "negative lookahead"),
            ("(?<=a)b", "lookbehind"),
            ("(?<!a)b", "negative lookbehind"),
            (r"(a)\1", "backreference"),
            (r"\k<name>", "named backreference"),
            ("[^a]", "negated class"),
            ("a*?", "lazy star"),
            ("a+?", "lazy plus"),
            ("a??", "lazy optional"),
            ("a{2}?", "lazy count"),
            ("a**", "stacked star"),
            ("a+*", "stacked plus"),
            ("a{2}{3}", "stacked count"),
            ("*a", "quantifier with nothing to repeat"),
            ("^*", "quantified anchor"),
            (r"\w", "word escape"),
            (r"\s", "space escape"),
            (r"\b", "word boundary"),
            (r"\B", "non-boundary"),
            (r"\D", "non-digit escape"),
            (r"\W", "non-word escape"),
            (r"\S", "non-space escape"),
            (r"\p{L}", "property escape"),
            (r"\P{L}", "negated property escape"),
            (r"\u0041", "unicode escape"),
            (r"\x41", "hex escape"),
            (r"\cA", "control escape"),
            (r"\n", "newline escape"),
            (r"\t", "tab escape"),
            (r"\0", "null escape"),
            (r"\a", "unknown identity escape"),
            ("\\", "trailing backslash"),
            ("[]", "empty class"),
            ("[a", "unterminated class"),
            ("[z-a]", "descending range"),
            (r"[\w]", "word escape in a class"),
            ("(?i)a", "inline flag"),
            ("a{2", "unterminated count"),
            ("a{,2}", "count without a minimum"),
            ("a{3,1}", "maximum below minimum"),
            ("a{1001}", "count above 1,000"),
            ("a{1,1001}", "maximum above 1,000"),
            (
                "\u{1F600}",
                "character outside the Basic Multilingual Plane",
            ),
            (too_long.as_str(), "longer than 256 characters"),
        ]
        .into_iter()
        .chain(UNICODE_MODE_SYNTAX_ERRORS.iter().copied())
        .chain(SURROGATE_RANGES.iter().copied())
        .filter(|(pattern, _)| Pattern::compile(pattern).is_ok())
        .map(|(pattern, excluded)| format!("{excluded}: {pattern}"))
        .collect::<Vec<_>>();
        assert!(accepted.is_empty(), "accepted: {accepted:?}");
    }

    /// Forms that are syntax errors under the `u` flag, which the subset refuses.
    pub(crate) const UNICODE_MODE_SYNTAX_ERRORS: &[(&str, &str)] = &[
        (r"a\-b", "escaped hyphen outside a class"),
        (r"^\-$", "anchored escaped hyphen outside a class"),
        (r"[\d-a]", "digit class as a range's low bound"),
        (
            r"^[\d-a-z]$",
            "digit class as a range's low bound before a range",
        ),
        (
            r"^[\d--a]$",
            "digit class as a range's low bound with a hyphen",
        ),
        (r"[\d-\d]", "digit class as both bounds of a range"),
        (r"[a-\d]", "digit class as a range's high bound"),
        (
            r"[--\d]",
            "digit class as a range's high bound after a hyphen",
        ),
    ];

    /// Class ranges that include U+D800 to U+DFFF, which the subset refuses.
    pub(crate) const SURROGATE_RANGES: &[(&str, &str)] = &[
        ("^[\u{D7FF}-\u{E000}]{2}$", "range spanning the surrogates"),
        ("[a-\u{FFFF}]", "range from ASCII over the surrogates"),
        ("[\u{0}-\u{FFFF}]", "range over the whole plane"),
    ];

    #[test]
    fn unicode_mode_syntax_errors_fail_closed() {
        let accepted = UNICODE_MODE_SYNTAX_ERRORS
            .iter()
            .filter(|(pattern, _)| Pattern::compile(pattern).is_ok())
            .collect::<Vec<_>>();
        assert!(accepted.is_empty(), "accepted: {accepted:?}");

        let refused = [
            "a-b",
            r"[a\-z]",
            r"[\-a]",
            "[-a]",
            "[a-]",
            r"[\d-]",
            r"[\d\-a]",
            r"[-\d]",
            r"[a-z-\d]",
        ]
        .into_iter()
        .filter(|pattern| Pattern::compile(pattern).is_err())
        .collect::<Vec<_>>();
        assert!(refused.is_empty(), "refused: {refused:?}");

        // `\-` in a class is a member, and so is `-` right after a range.
        for (input, expected) in [("-", true), ("5", true), ("a", true), ("b", false)] {
            assert_eq!(matches(r"^[\d\-a]$", input), expected, "{input}");
        }
        for (input, expected) in [("-", true), ("5", true), ("m", true), ("A", false)] {
            assert_eq!(matches(r"^[a-z-\d]$", input), expected, "{input}");
        }
        assert!(matches(r"^\d{3}-[a\-z]$", "123--"));
    }

    #[test]
    fn ranges_that_include_surrogates_fail_closed() {
        let accepted = SURROGATE_RANGES
            .iter()
            .filter(|(pattern, _)| Pattern::compile(pattern).is_ok())
            .collect::<Vec<_>>();
        assert!(accepted.is_empty(), "accepted: {accepted:?}");

        for pattern in ["[a-\u{D7FF}]", "[\u{E000}-\u{FFFF}]"] {
            assert!(Pattern::compile(pattern).is_ok(), "{pattern}");
        }
        assert!(matches("^[\u{E000}-\u{FFFF}]$", "\u{E000}"));
        assert!(!matches("^[\u{E000}-\u{FFFF}]$", "\u{1F600}"));
    }
}
