//! Validation against an exact JSON Schema Draft 2020-12 artifact.
//!
//! The validator interprets the artifact it is given, so the pinned schema bytes, and nothing
//! compiled into this crate, decide what a valid document is. It supports the keywords the
//! approved artifacts use. Any other keyword, any other `format`, or a malformed keyword value
//! makes the artifact unsupported, so validation fails closed rather than silently ignoring a
//! constraint.
//!
//! Supported assertions: `type`, `enum`, `const`, `minLength`, `maxLength`, `pattern`, `format`
//! (`date` only, asserted as an RFC 3339 `full-date`), `minimum`, `maximum`, `minItems`,
//! `maxItems`, `uniqueItems`, `items`, `properties`, `required`, `additionalProperties`,
//! `minProperties`, and `maxProperties`. Accepted annotations: `$schema` and `$id` at the root,
//! and `title`, `description`, and `$comment` anywhere.

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::{DomainError, canonicalize, pattern::Pattern, time::is_full_date};

const DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";
const MAX_SCHEMA_NODES: usize = 1_024;
const MAX_KEYWORD_ENTRIES: usize = 256;

/// A schema artifact compiled for validation.
#[derive(Clone, Debug)]
pub struct CompiledSchema {
    id: String,
    root: Node,
}

impl CompiledSchema {
    /// Compiles a strictly parsed Draft 2020-12 artifact.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::UnsupportedSchema`] when the root is not an object declaring the
    /// Draft 2020-12 `$schema` and a string `$id`, when it uses an unsupported keyword or
    /// `format`, or when a keyword value is malformed or exceeds the collection bounds.
    pub fn compile(artifact: &Value) -> Result<Self, DomainError> {
        let object = artifact.as_object().ok_or(DomainError::UnsupportedSchema)?;
        if object.get("$schema").and_then(Value::as_str) != Some(DRAFT_2020_12) {
            return Err(DomainError::UnsupportedSchema);
        }
        let id = object
            .get("$id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 128 && id.is_ascii())
            .ok_or(DomainError::UnsupportedSchema)?
            .to_owned();
        let mut budget = MAX_SCHEMA_NODES;
        let root = Node::compile(artifact, true, &mut budget)?;
        Ok(Self { id, root })
    }

    /// Returns the artifact's `$id`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Validates a strictly parsed document.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError::Schema`] when any assertion fails. The error names no value.
    pub fn validate(&self, document: &Value) -> Result<(), DomainError> {
        if self.root.accepts(document)? {
            Ok(())
        } else {
            Err(DomainError::Schema)
        }
    }
}

#[derive(Clone, Debug)]
enum Node {
    Boolean(bool),
    Keywords(Box<Keywords>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum JsonType {
    Null,
    Boolean,
    Object,
    Array,
    Number,
    Integer,
    String,
}

impl JsonType {
    fn parse(name: &str) -> Result<Self, DomainError> {
        Ok(match name {
            "null" => Self::Null,
            "boolean" => Self::Boolean,
            "object" => Self::Object,
            "array" => Self::Array,
            "number" => Self::Number,
            "integer" => Self::Integer,
            "string" => Self::String,
            _ => return Err(DomainError::UnsupportedSchema),
        })
    }

    fn accepts(self, value: &Value) -> bool {
        match self {
            Self::Null => value.is_null(),
            Self::Boolean => value.is_boolean(),
            Self::Object => value.is_object(),
            Self::Array => value.is_array(),
            // The strict profile admits only integers, so every number is an integer.
            Self::Number | Self::Integer => value.is_number(),
            Self::String => value.is_string(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Keywords {
    types: Option<Vec<JsonType>>,
    enumeration: Option<Vec<Value>>,
    constant: Option<Value>,
    min_length: Option<u64>,
    max_length: Option<u64>,
    pattern: Option<Pattern>,
    full_date: bool,
    minimum: Option<i64>,
    maximum: Option<i64>,
    min_items: Option<u64>,
    max_items: Option<u64>,
    unique_items: bool,
    items: Option<Node>,
    properties: Vec<(String, Node)>,
    required: Vec<String>,
    additional_properties: Option<Node>,
    min_properties: Option<u64>,
    max_properties: Option<u64>,
}

impl Node {
    fn compile(value: &Value, root: bool, budget: &mut usize) -> Result<Self, DomainError> {
        *budget = budget
            .checked_sub(1)
            .ok_or(DomainError::UnsupportedSchema)?;
        match value {
            Value::Bool(value) => Ok(Self::Boolean(*value)),
            Value::Object(object) => Ok(Self::Keywords(Box::new(Keywords::compile(
                object, root, budget,
            )?))),
            _ => Err(DomainError::UnsupportedSchema),
        }
    }

    fn accepts(&self, value: &Value) -> Result<bool, DomainError> {
        match self {
            Self::Boolean(accepts) => Ok(*accepts),
            Self::Keywords(keywords) => keywords.accepts(value),
        }
    }
}

impl Keywords {
    fn compile(
        object: &Map<String, Value>,
        root: bool,
        budget: &mut usize,
    ) -> Result<Self, DomainError> {
        let mut keywords = Self::default();
        for (name, value) in object {
            match name.as_str() {
                "$schema" | "$id" if root => {}
                "title" | "description" | "$comment" => {
                    value.as_str().ok_or(DomainError::UnsupportedSchema)?;
                }
                "type" => keywords.types = Some(compile_types(value)?),
                "enum" => {
                    let values = value
                        .as_array()
                        .filter(|values| !values.is_empty() && values.len() <= MAX_KEYWORD_ENTRIES)
                        .ok_or(DomainError::UnsupportedSchema)?;
                    keywords.enumeration =
                        Some(values.iter().map(profile_value).collect::<Result<_, _>>()?);
                }
                "const" => keywords.constant = Some(profile_value(value)?),
                "minLength" => keywords.min_length = Some(non_negative(value)?),
                "maxLength" => keywords.max_length = Some(non_negative(value)?),
                "pattern" => {
                    let source = value.as_str().ok_or(DomainError::UnsupportedSchema)?;
                    keywords.pattern = Some(Pattern::compile(source)?);
                }
                "format" => {
                    if value.as_str() != Some("date") {
                        return Err(DomainError::UnsupportedSchema);
                    }
                    keywords.full_date = true;
                }
                "minimum" => keywords.minimum = Some(integer(value)?),
                "maximum" => keywords.maximum = Some(integer(value)?),
                "minItems" => keywords.min_items = Some(non_negative(value)?),
                "maxItems" => keywords.max_items = Some(non_negative(value)?),
                "uniqueItems" => {
                    keywords.unique_items =
                        value.as_bool().ok_or(DomainError::UnsupportedSchema)?;
                }
                "items" => keywords.items = Some(Node::compile(value, false, budget)?),
                "properties" => {
                    let properties = value
                        .as_object()
                        .filter(|properties| properties.len() <= MAX_KEYWORD_ENTRIES)
                        .ok_or(DomainError::UnsupportedSchema)?;
                    for (property, schema) in properties {
                        keywords
                            .properties
                            .push((property.clone(), Node::compile(schema, false, budget)?));
                    }
                }
                "required" => {
                    let required = value
                        .as_array()
                        .filter(|required| required.len() <= MAX_KEYWORD_ENTRIES)
                        .ok_or(DomainError::UnsupportedSchema)?;
                    let mut unique = HashSet::new();
                    for property in required {
                        let property = property.as_str().ok_or(DomainError::UnsupportedSchema)?;
                        if !unique.insert(property) {
                            return Err(DomainError::UnsupportedSchema);
                        }
                        keywords.required.push(property.to_owned());
                    }
                }
                "additionalProperties" => {
                    keywords.additional_properties = Some(Node::compile(value, false, budget)?);
                }
                "minProperties" => keywords.min_properties = Some(non_negative(value)?),
                "maxProperties" => keywords.max_properties = Some(non_negative(value)?),
                _ => return Err(DomainError::UnsupportedSchema),
            }
        }
        Ok(keywords)
    }

    fn accepts(&self, value: &Value) -> Result<bool, DomainError> {
        if let Some(types) = &self.types
            && !types.iter().any(|kind| kind.accepts(value))
        {
            return Ok(false);
        }
        if let Some(values) = &self.enumeration
            && !values.contains(value)
        {
            return Ok(false);
        }
        if self
            .constant
            .as_ref()
            .is_some_and(|constant| constant != value)
        {
            return Ok(false);
        }
        let accepted = match value {
            Value::String(text) => self.accepts_string(text),
            Value::Number(number) => self.accepts_integer(number.as_i64()),
            Value::Array(items) => self.accepts_array(items)?,
            Value::Object(members) => self.accepts_object(members)?,
            Value::Null | Value::Bool(_) => true,
        };
        Ok(accepted)
    }

    fn accepts_string(&self, text: &str) -> bool {
        let length = u64::try_from(text.chars().count()).unwrap_or(u64::MAX);
        !(self.min_length.is_some_and(|min| length < min)
            || self.max_length.is_some_and(|max| length > max)
            || self
                .pattern
                .as_ref()
                .is_some_and(|pattern| !pattern.is_match(text))
            || (self.full_date && !is_full_date(text)))
    }

    fn accepts_integer(&self, number: Option<i64>) -> bool {
        // The strict profile keeps every integer within i64, so `None` cannot occur.
        number.is_some_and(|number| {
            !(self.minimum.is_some_and(|min| number < min)
                || self.maximum.is_some_and(|max| number > max))
        })
    }

    fn accepts_array(&self, items: &[Value]) -> Result<bool, DomainError> {
        let count = u64::try_from(items.len()).unwrap_or(u64::MAX);
        if self.min_items.is_some_and(|min| count < min)
            || self.max_items.is_some_and(|max| count > max)
        {
            return Ok(false);
        }
        if self.unique_items {
            // Under the strict integer-only profile, two values are equal exactly when their
            // RFC 8785 forms are equal, so hashing canonical bytes checks uniqueness in linear time.
            let mut seen = HashSet::with_capacity(items.len());
            for item in items {
                if !seen.insert(canonicalize(item)?) {
                    return Ok(false);
                }
            }
        }
        if let Some(schema) = &self.items {
            for item in items {
                if !schema.accepts(item)? {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn accepts_object(&self, members: &Map<String, Value>) -> Result<bool, DomainError> {
        let count = u64::try_from(members.len()).unwrap_or(u64::MAX);
        if self.min_properties.is_some_and(|min| count < min)
            || self.max_properties.is_some_and(|max| count > max)
            || self
                .required
                .iter()
                .any(|property| !members.contains_key(property))
        {
            return Ok(false);
        }
        for (name, member) in members {
            let schema = self
                .properties
                .iter()
                .find(|(property, _)| property == name)
                .map(|(_, schema)| schema)
                .or(self.additional_properties.as_ref());
            if let Some(schema) = schema
                && !schema.accepts(member)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn compile_types(value: &Value) -> Result<Vec<JsonType>, DomainError> {
    match value {
        Value::String(name) => Ok(vec![JsonType::parse(name)?]),
        Value::Array(names) if !names.is_empty() && names.len() <= 7 => {
            let mut types = Vec::with_capacity(names.len());
            for name in names {
                let parsed = JsonType::parse(name.as_str().ok_or(DomainError::UnsupportedSchema)?)?;
                // The meta-schema requires the names to be unique.
                if types.contains(&parsed) {
                    return Err(DomainError::UnsupportedSchema);
                }
                types.push(parsed);
            }
            Ok(types)
        }
        _ => Err(DomainError::UnsupportedSchema),
    }
}

/// An `enum` or `const` value, which must lie inside the strict integer profile documents use.
fn profile_value(value: &Value) -> Result<Value, DomainError> {
    canonicalize(value).map_err(|_| DomainError::UnsupportedSchema)?;
    Ok(value.clone())
}

fn non_negative(value: &Value) -> Result<u64, DomainError> {
    value.as_u64().ok_or(DomainError::UnsupportedSchema)
}

fn integer(value: &Value) -> Result<i64, DomainError> {
    value.as_i64().ok_or(DomainError::UnsupportedSchema)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::parse_document;

    fn artifact() -> Value {
        parse_document(include_bytes!(
            "../../../schemas/service-application/1.0.0.schema.json"
        ))
        .expect("approved artifact")
        .value()
        .clone()
    }

    fn document(bytes: &[u8]) -> Value {
        parse_document(bytes).expect("strict JSON").value().clone()
    }

    fn valid() -> Value {
        document(include_bytes!(
            "../../../schemas/service-application/example.json"
        ))
    }

    #[test]
    fn approved_artifact_accepts_the_invented_example() {
        let schema = CompiledSchema::compile(&artifact()).expect("supported artifact");
        assert_eq!(schema.id(), "urn:docchain:schema:service-application:1.0.0");
        assert_eq!(schema.validate(&valid()), Ok(()));
    }

    #[test]
    fn approved_artifact_rejects_each_violated_keyword() {
        let schema = CompiledSchema::compile(&artifact()).expect("supported artifact");
        let cases: [(&str, Value); 10] = [
            ("applicationReference", Value::from("SYN-abc")),
            ("serviceCode", Value::from("other")),
            ("submittedOn", Value::from("2026-02-29")),
            ("submittedOn", Value::from(20_260_919)),
            ("statement", Value::from("")),
            ("statement", Value::from("x".repeat(2_001))),
            (
                "declarations",
                serde_json::json!(["no-legal-effect", "no-legal-effect"]),
            ),
            ("declarations", serde_json::json!(["invented"])),
            (
                "declarations",
                Value::Array(vec![Value::from("no-legal-effect"); 11]),
            ),
            ("unexpected", Value::Bool(true)),
        ];
        for (member, replacement) in cases {
            let mut candidate = valid();
            candidate
                .as_object_mut()
                .expect("object")
                .insert(member.to_owned(), replacement);
            assert_eq!(
                schema.validate(&candidate),
                Err(DomainError::Schema),
                "{member}"
            );
        }
        let mut missing = valid();
        missing.as_object_mut().expect("object").remove("statement");
        assert_eq!(schema.validate(&missing), Err(DomainError::Schema));
    }

    #[test]
    fn dates_before_1970_are_valid_full_dates() {
        let schema = CompiledSchema::compile(&artifact()).expect("supported artifact");
        let mut candidate = valid();
        candidate["submittedOn"] = Value::from("1969-07-20");
        assert_eq!(schema.validate(&candidate), Ok(()));
    }

    #[test]
    fn validation_follows_the_artifact_it_is_given() {
        let mut edited = artifact();
        edited["properties"]["statement"]["maxLength"] = Value::from(3);
        let schema = CompiledSchema::compile(&edited).expect("supported artifact");
        assert_eq!(schema.validate(&valid()), Err(DomainError::Schema));
    }

    #[test]
    fn integer_bounds_are_inclusive() {
        let schema = CompiledSchema::compile(&json!({
            "$schema": DRAFT_2020_12,
            "$id": "urn:docchain:test:bounds",
            "minimum": -2,
            "maximum": 300,
        }))
        .expect("supported bounds");
        for (instance, valid) in [
            (json!(-3), false),
            (json!(-2), true),
            (json!(300), true),
            (json!(301), false),
            (json!("x"), true),
        ] {
            assert_eq!(schema.validate(&instance).is_ok(), valid, "{instance}");
        }
    }

    #[test]
    fn unsupported_keywords_formats_and_drafts_fail_closed() {
        fn edited(change: impl FnOnce(&mut Value)) -> Value {
            let mut schema = artifact();
            change(&mut schema);
            schema
        }
        fn at_statement(keyword: &str, value: Value) -> Value {
            edited(|schema| schema["properties"]["statement"][keyword] = value)
        }
        let mut cases: Vec<(String, Value)> = Vec::new();

        // Every Draft 2020-12 keyword outside the subset, and an unknown one.
        for keyword in [
            "$ref",
            "$defs",
            "$anchor",
            "$dynamicRef",
            "$dynamicAnchor",
            "$vocabulary",
            "allOf",
            "anyOf",
            "oneOf",
            "not",
            "if",
            "then",
            "else",
            "dependentRequired",
            "dependentSchemas",
            "prefixItems",
            "contains",
            "minContains",
            "maxContains",
            "patternProperties",
            "propertyNames",
            "unevaluatedItems",
            "unevaluatedProperties",
            "exclusiveMinimum",
            "exclusiveMaximum",
            "multipleOf",
            "contentEncoding",
            "contentMediaType",
            "contentSchema",
            "default",
            "examples",
            "deprecated",
            "readOnly",
            "writeOnly",
            "definitions",
            "x-unknown",
        ] {
            cases.push((
                format!("keyword {keyword}"),
                at_statement(keyword, json!(true)),
            ));
        }
        cases.push((
            "keyword at the root".to_owned(),
            edited(|schema| schema["allOf"] = json!([])),
        ));

        // Every Draft 2020-12 format other than date, and an unknown one.
        for format in [
            "date-time",
            "time",
            "duration",
            "email",
            "idn-email",
            "hostname",
            "idn-hostname",
            "ipv4",
            "ipv6",
            "uri",
            "uri-reference",
            "iri",
            "iri-reference",
            "uuid",
            "uri-template",
            "json-pointer",
            "relative-json-pointer",
            "regex",
            "x-unknown",
        ] {
            cases.push((
                format!("format {format}"),
                at_statement("format", json!(format)),
            ));
        }

        // Drafts, roots, and identifiers.
        let malformed: Vec<(&str, Value)> = vec![
            (
                "draft-07",
                edited(|schema| {
                    schema["$schema"] = json!("http://json-schema.org/draft-07/schema#");
                }),
            ),
            (
                "missing $schema",
                edited(|schema| {
                    schema.as_object_mut().map(|root| root.remove("$schema"));
                }),
            ),
            (
                "missing $id",
                edited(|schema| {
                    schema.as_object_mut().map(|root| root.remove("$id"));
                }),
            ),
            ("empty $id", edited(|schema| schema["$id"] = json!(""))),
            ("non-string $id", edited(|schema| schema["$id"] = json!(1))),
            (
                "$id over 128 bytes",
                edited(|schema| schema["$id"] = json!(format!("urn:{}", "a".repeat(125)))),
            ),
            (
                "non-ASCII $id",
                edited(|schema| schema["$id"] = json!("urn:é")),
            ),
            ("nested $id", at_statement("$id", json!("urn:nested"))),
            (
                "nested $schema",
                at_statement("$schema", artifact()["$schema"].clone()),
            ),
            ("boolean root", json!(true)),
            ("array root", json!([])),
            ("non-string title", at_statement("title", json!(1))),
            (
                "non-string description",
                at_statement("description", json!(1)),
            ),
            ("non-string $comment", at_statement("$comment", json!(1))),
            // Keyword values.
            ("unknown type name", at_statement("type", json!("text"))),
            (
                "duplicate type names",
                at_statement("type", json!(["string", "string"])),
            ),
            ("empty type array", at_statement("type", json!([]))),
            ("non-string type", at_statement("type", json!(1))),
            ("non-array enum", at_statement("enum", json!("a"))),
            ("empty enum", at_statement("enum", json!([]))),
            (
                "enum over 256 values",
                at_statement("enum", Value::Array((0..257).map(Value::from).collect())),
            ),
            ("fractional enum value", at_statement("enum", json!([1.5]))),
            (
                "integral float enum value",
                at_statement("enum", json!([2.0])),
            ),
            ("fractional const", at_statement("const", json!(1.5))),
            ("integral float const", at_statement("const", json!(-2.0))),
            (
                "const beyond the safe integer range",
                at_statement("const", json!(9_007_199_254_740_992_u64)),
            ),
            ("negative minLength", at_statement("minLength", json!(-1))),
            (
                "fractional minLength",
                at_statement("minLength", json!(1.5)),
            ),
            ("string maxLength", at_statement("maxLength", json!("2"))),
            ("non-string pattern", at_statement("pattern", json!(1))),
            ("non-string format", at_statement("format", json!(1))),
            ("fractional minimum", at_statement("minimum", json!(1.5))),
            ("string maximum", at_statement("maximum", json!("1"))),
            (
                "maximum beyond the signed 64-bit range",
                at_statement("maximum", json!(u64::MAX)),
            ),
            (
                "negative minItems",
                edited(|schema| schema["properties"]["declarations"]["minItems"] = json!(-1)),
            ),
            (
                "fractional maxItems",
                edited(|schema| schema["properties"]["declarations"]["maxItems"] = json!(2.5)),
            ),
            (
                "non-boolean uniqueItems",
                edited(|schema| schema["properties"]["declarations"]["uniqueItems"] = json!(1)),
            ),
            (
                "array-form items",
                edited(|schema| schema["properties"]["declarations"]["items"] = json!([{}])),
            ),
            (
                "numeric items",
                edited(|schema| schema["properties"]["declarations"]["items"] = json!(1)),
            ),
            (
                "array properties",
                edited(|schema| schema["properties"] = json!([])),
            ),
            (
                "properties over 256 members",
                edited(|schema| {
                    schema["properties"] = Value::Object(
                        (0..257)
                            .map(|index| (format!("p{index}"), json!({})))
                            .collect(),
                    );
                }),
            ),
            (
                "non-array required",
                edited(|schema| schema["required"] = json!("a")),
            ),
            (
                "duplicate required names",
                edited(|schema| schema["required"] = json!(["statement", "statement"])),
            ),
            (
                "non-string required name",
                edited(|schema| schema["required"] = json!([1])),
            ),
            (
                "required over 256 names",
                edited(|schema| {
                    schema["required"] =
                        Value::Array((0..257).map(|index| json!(format!("p{index}"))).collect());
                }),
            ),
            (
                "numeric additionalProperties",
                edited(|schema| schema["additionalProperties"] = json!(1)),
            ),
            (
                "negative minProperties",
                edited(|schema| schema["minProperties"] = json!(-1)),
            ),
            (
                "string maxProperties",
                edited(|schema| schema["maxProperties"] = json!("1")),
            ),
            (
                "pattern outside the subset",
                at_statement("pattern", json!("^(SYN)$")),
            ),
            (
                "more than 1,024 schema nodes",
                edited(|schema| {
                    let mut deep = json!({});
                    for _ in 0..30 {
                        deep = json!({"items": deep});
                    }
                    schema["properties"] = Value::Object(
                        (0..40)
                            .map(|index| (format!("p{index}"), deep.clone()))
                            .collect(),
                    );
                }),
            ),
        ];
        cases.extend(
            malformed
                .into_iter()
                .map(|(name, schema)| (name.to_owned(), schema)),
        );

        // Pattern forms that are syntax errors under the `u` flag, and surrogate-spanning ranges.
        for (pattern, excluded) in crate::pattern::tests::UNICODE_MODE_SYNTAX_ERRORS
            .iter()
            .chain(crate::pattern::tests::SURROGATE_RANGES)
        {
            cases.push((
                format!("pattern {excluded}: {pattern}"),
                at_statement("pattern", json!(pattern)),
            ));
        }

        let accepted = cases
            .into_iter()
            .filter(|(_, schema)| {
                CompiledSchema::compile(schema).map(|_| ()) != Err(DomainError::UnsupportedSchema)
            })
            .map(|(name, _)| name)
            .collect::<Vec<_>>();
        assert!(
            accepted.is_empty(),
            "not refused as unsupported: {accepted:?}"
        );
    }
}
