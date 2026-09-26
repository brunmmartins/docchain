use std::{cmp::Ordering, collections::BTreeSet, fmt};

use serde::{
    Deserializer,
    de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor},
};
use serde_json::Value;

use crate::{DomainError, MAX_DOCUMENT_BYTES, MAX_JSON_DEPTH, MAX_SAFE_INTEGER};

/// A strictly parsed JSON value with its RFC 8785 canonical bytes.
///
/// `Debug` is redacted: the value may be document plaintext. The canonical bytes are overwritten
/// on drop; overwriting is best effort, and the parsed value is not cleared.
#[derive(Clone)]
pub struct CanonicalDocument {
    value: Value,
    bytes: Vec<u8>,
}

impl Drop for CanonicalDocument {
    fn drop(&mut self) {
        self.bytes.fill(0);
        std::hint::black_box(&self.bytes);
    }
}

impl fmt::Debug for CanonicalDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalDocument(redacted)")
    }
}

impl CanonicalDocument {
    /// The parsed value.
    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.value
    }

    /// The RFC 8785 canonical bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Strictly parses and canonicalizes a document within the 256 KiB and depth-32 bounds.
///
/// # Errors
///
/// As [`parse_bounded_json`].
pub fn parse_document(input: &[u8]) -> Result<CanonicalDocument, DomainError> {
    parse_bounded_json(input, MAX_DOCUMENT_BYTES, MAX_JSON_DEPTH)
}

/// Strictly parses and canonicalizes JSON within caller-supplied byte and depth bounds.
///
/// This is used for protocol JSON whose bound differs from the document bound.
/// Duplicate names, unsupported number forms, trailing data, and canonical output
/// larger than `max_bytes` are rejected.
///
/// # Errors
///
/// Returns [`DomainError::Bound`] for oversize input or output and [`DomainError::InvalidJson`]
/// for anything outside the strict profile, including excess depth.
pub fn parse_bounded_json(
    input: &[u8],
    max_bytes: usize,
    max_depth: usize,
) -> Result<CanonicalDocument, DomainError> {
    if max_depth == 0 || input.len() > max_bytes {
        return Err(DomainError::Bound("raw document size"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(input);
    let value = StrictSeed {
        depth: 1,
        max_depth,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| DomainError::InvalidJson)?;
    deserializer.end().map_err(|_| DomainError::InvalidJson)?;
    let bytes = canonicalize(&value)?;
    if bytes.len() > max_bytes {
        return Err(DomainError::Bound("canonical document size"));
    }
    Ok(CanonicalDocument { value, bytes })
}

/// Serializes a strict-profile value as RFC 8785 JCS bytes.
///
/// # Errors
///
/// Returns [`DomainError::InvalidJson`] for a number outside the integer profile.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, DomainError> {
    let mut output = Vec::new();
    write_canonical(value, &mut output)?;
    Ok(output)
}

fn write_canonical(value: &Value, output: &mut Vec<u8>) -> Result<(), DomainError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" });
        }
        Value::Number(number) => {
            let accepted = number
                .as_i64()
                .filter(|number| number.unsigned_abs() <= MAX_SAFE_INTEGER)
                .map(|number| number.to_string())
                .or_else(|| {
                    number
                        .as_u64()
                        .filter(|number| *number <= MAX_SAFE_INTEGER)
                        .map(|number| number.to_string())
                })
                .ok_or(DomainError::InvalidJson)?;
            output.extend_from_slice(accepted.as_bytes());
        }
        Value::String(value) => {
            let escaped = serde_json::to_string(value).map_err(|_| DomainError::InvalidJson)?;
            output.extend_from_slice(escaped.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut values = values.iter().collect::<Vec<_>>();
            values.sort_by(|(left, _), (right, _)| compare_utf16(left, right));
            for (index, (key, value)) in values.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                let key = serde_json::to_string(key).map_err(|_| DomainError::InvalidJson)?;
                output.extend_from_slice(key.as_bytes());
                output.push(b':');
                write_canonical(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn compare_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

struct StrictSeed {
    depth: usize,
    max_depth: usize,
}

impl<'de> DeserializeSeed<'de> for StrictSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor {
            depth: self.depth,
            max_depth: self.max_depth,
        })
    }
}

struct StrictVisitor {
    depth: usize,
    max_depth: usize,
}

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict-profile JSON")
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E>
    where
        E: serde::de::Error,
    {
        if value.unsigned_abs() > MAX_SAFE_INTEGER {
            return Err(E::custom("integer outside exact range"));
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E>
    where
        E: serde::de::Error,
    {
        if value > MAX_SAFE_INTEGER {
            return Err(E::custom("integer outside exact range"));
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Value, E>
    where
        E: serde::de::Error,
    {
        Err(E::custom("unsupported number form"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if self.depth > self.max_depth {
            return Err(A::Error::custom("JSON depth exceeded"));
        }
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictSeed {
            depth: self.depth + 1,
            max_depth: self.max_depth,
        })? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth > self.max_depth {
            return Err(A::Error::custom("JSON depth exceeded"));
        }
        let mut seen = BTreeSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(A::Error::custom("duplicate object name"));
            }
            let value = map.next_value_seed(StrictSeed {
                depth: self.depth + 1,
                max_depth: self.max_depth,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}
