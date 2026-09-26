//! Conformance of the schema interpreter to the pinned official JSON Schema Test Suite, plus
//! Docchain gap cases for directions the pinned suite lacks.
//!
//! The suite files under `tests/vectors/json-schema-test-suite/` are unmodified copies from
//! JSON-Schema-Test-Suite at commit `7741b279ca22de18fb14bfd4d0f4fca011ffca1f`, MIT licensed. Every
//! case falls into exactly one class: it runs and must agree with the suite; its schema is outside
//! the supported subset and must fail to compile as unsupported; or its instance is outside the
//! strict JSON profile and must be refused by the strict parser. Each case of the last two classes
//! is listed below with its reason, so the subset boundary cannot move without this file changing.
//!
//! Every supported keyword needs a valid and an invalid run case. A valid case counts for a
//! keyword only when the keyword reaches a value of the type it constrains. An invalid case counts
//! for a keyword only when removing that keyword makes the instance valid. Gap cases under
//! `tests/vectors/schema-cases/` may supply only a direction that no suite case covers; their
//! expectations come from the Draft 2020-12 Validation text, never from the interpreter.

use std::collections::{BTreeMap, BTreeSet};

use docchain_domain::{CompiledSchema, DomainError, parse_document};
use serde_json::{Map, Value, json};

const SUITE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/vectors/json-schema-test-suite/tests/draft2020-12/"
);

/// Docchain gap cases, one `<keyword>.json` file per keyword, in the suite's format.
const GAP_CASES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/vectors/");
const GAP_DIRECTORY: &str = "schema-cases";

const FILES: [&str; 20] = [
    "additionalProperties",
    "const",
    "enum",
    "format",
    "items",
    "maxItems",
    "maxLength",
    "maxProperties",
    "maximum",
    "minItems",
    "minLength",
    "minProperties",
    "minimum",
    "pattern",
    "properties",
    "required",
    "type",
    "uniqueItems",
    "optional/format/date",
    "optional/ecmascript-regex",
];

/// Every supported assertion or applicator; each needs a valid and an invalid run case.
const SUPPORTED: [&str; 18] = [
    "type",
    "enum",
    "const",
    "minLength",
    "maxLength",
    "pattern",
    "format",
    "minimum",
    "maximum",
    "minItems",
    "maxItems",
    "uniqueItems",
    "items",
    "properties",
    "required",
    "additionalProperties",
    "minProperties",
    "maxProperties",
];

/// The only suite run case that credits `maximum` as valid. The suite's other `maximum` cases
/// use a fractional bound or fractional instances, which the subset and the strict profile
/// refuse, so the invalid direction comes from the gap file.
const MAXIMUM_VALID_SOURCE: &str =
    "maximum / maximum validation with unsigned integer / boundary point integer is valid";

/// The one deliberate inversion: `format: "date"` is asserted, not an annotation.
const ASSERTED_FORMAT: (&str, &str, &str) = (
    "format",
    "date format",
    "invalid date string is only an annotation by default",
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Run,
    OutsideSubset,
    OutsideProfile,
}

const SUBSET: Class = Class::OutsideSubset;
const PROFILE: Class = Class::OutsideProfile;

/// File, group, and case descriptions of every case that does not run, with its class and reason.
const EXCLUDED: &[(&str, &str, &str, Class, &str)] = &[
    (
        "additionalProperties",
        "additionalProperties being false does not allow other properties",
        "no additional properties is valid",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "additionalProperties",
        "additionalProperties being false does not allow other properties",
        "an additional property is invalid",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "additionalProperties",
        "additionalProperties being false does not allow other properties",
        "ignores arrays",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "additionalProperties",
        "additionalProperties being false does not allow other properties",
        "ignores strings",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "additionalProperties",
        "additionalProperties being false does not allow other properties",
        "ignores other non-objects",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "additionalProperties",
        "additionalProperties being false does not allow other properties",
        "patternProperties are not additional properties",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "additionalProperties",
        "non-ASCII pattern with additionalProperties",
        "matching the pattern is valid",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "additionalProperties",
        "non-ASCII pattern with additionalProperties",
        "not matching the pattern is invalid",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "additionalProperties",
        "additionalProperties does not look in applicators",
        "properties defined in allOf are not examined",
        SUBSET,
        "keyword allOf",
    ),
    (
        "additionalProperties",
        "additionalProperties with propertyNames",
        "Valid against both keywords",
        SUBSET,
        "keyword propertyNames",
    ),
    (
        "additionalProperties",
        "additionalProperties with propertyNames",
        "Valid against propertyNames, but not additionalProperties",
        SUBSET,
        "keyword propertyNames",
    ),
    (
        "additionalProperties",
        "dependentSchemas with additionalProperties",
        "additionalProperties doesn't consider dependentSchemas",
        SUBSET,
        "keyword dependentSchemas",
    ),
    (
        "additionalProperties",
        "dependentSchemas with additionalProperties",
        "additionalProperties can't see bar",
        SUBSET,
        "keyword dependentSchemas",
    ),
    (
        "additionalProperties",
        "dependentSchemas with additionalProperties",
        "additionalProperties can't see bar even when foo2 is present",
        SUBSET,
        "keyword dependentSchemas",
    ),
    (
        "const",
        "const with false does not match 0",
        "float zero is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "const",
        "const with true does not match 1",
        "float one is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "const",
        "const with [false] does not match [0]",
        "[0.0] is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "const",
        "const with [true] does not match [1]",
        "[1.0] is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "const",
        "const with {\"a\": false} does not match {\"a\": 0}",
        "{\"a\": 0.0} is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "const",
        "const with {\"a\": true} does not match {\"a\": 1}",
        "{\"a\": 1.0} is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "const",
        "const with 0 does not match other zero-like types",
        "float zero is valid",
        PROFILE,
        "non-integer number",
    ),
    (
        "const",
        "const with 1 does not match true",
        "float one is valid",
        PROFILE,
        "non-integer number",
    ),
    (
        "const",
        "const with -2.0 matches integer and float types",
        "integer -2 is valid",
        SUBSET,
        "non-integer const value",
    ),
    (
        "const",
        "const with -2.0 matches integer and float types",
        "integer 2 is invalid",
        SUBSET,
        "non-integer const value",
    ),
    (
        "const",
        "const with -2.0 matches integer and float types",
        "float -2.0 is valid",
        SUBSET,
        "non-integer const value",
    ),
    (
        "const",
        "const with -2.0 matches integer and float types",
        "float 2.0 is invalid",
        SUBSET,
        "non-integer const value",
    ),
    (
        "const",
        "const with -2.0 matches integer and float types",
        "float -2.00001 is invalid",
        SUBSET,
        "non-integer const value",
    ),
    (
        "const",
        "float and integers are equal up to 64-bit representation limits",
        "integer is valid",
        SUBSET,
        "const beyond the safe integer range",
    ),
    (
        "const",
        "float and integers are equal up to 64-bit representation limits",
        "integer minus one is invalid",
        SUBSET,
        "const beyond the safe integer range",
    ),
    (
        "const",
        "float and integers are equal up to 64-bit representation limits",
        "float is valid",
        SUBSET,
        "const beyond the safe integer range",
    ),
    (
        "const",
        "float and integers are equal up to 64-bit representation limits",
        "float minus one is invalid",
        SUBSET,
        "const beyond the safe integer range",
    ),
    (
        "enum",
        "enum with false does not match 0",
        "float zero is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "enum",
        "enum with [false] does not match [0]",
        "[0.0] is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "enum",
        "enum with true does not match 1",
        "float one is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "enum",
        "enum with [true] does not match [1]",
        "[1.0] is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "enum",
        "enum with 0 does not match false",
        "float zero is valid",
        PROFILE,
        "non-integer number",
    ),
    (
        "enum",
        "enum with [0] does not match [false]",
        "[0.0] is valid",
        PROFILE,
        "non-integer number",
    ),
    (
        "enum",
        "enum with 1 does not match true",
        "float one is valid",
        PROFILE,
        "non-integer number",
    ),
    (
        "enum",
        "enum with [1] does not match [true]",
        "[1.0] is valid",
        PROFILE,
        "non-integer number",
    ),
    (
        "enum",
        "empty enum",
        "string is invalid",
        SUBSET,
        "empty enum; the subset needs 1 to 256 values",
    ),
    (
        "enum",
        "empty enum",
        "number is invalid",
        SUBSET,
        "empty enum; the subset needs 1 to 256 values",
    ),
    (
        "enum",
        "empty enum",
        "null is invalid",
        SUBSET,
        "empty enum; the subset needs 1 to 256 values",
    ),
    (
        "enum",
        "empty enum",
        "object is invalid",
        SUBSET,
        "empty enum; the subset needs 1 to 256 values",
    ),
    (
        "enum",
        "empty enum",
        "array is invalid",
        SUBSET,
        "empty enum; the subset needs 1 to 256 values",
    ),
    (
        "enum",
        "empty enum",
        "boolean is invalid",
        SUBSET,
        "empty enum; the subset needs 1 to 256 values",
    ),
    (
        "format",
        "email format",
        "all string formats ignore integers",
        SUBSET,
        "format email",
    ),
    (
        "format",
        "email format",
        "all string formats ignore floats",
        SUBSET,
        "format email",
    ),
    (
        "format",
        "email format",
        "all string formats ignore objects",
        SUBSET,
        "format email",
    ),
    (
        "format",
        "email format",
        "all string formats ignore arrays",
        SUBSET,
        "format email",
    ),
    (
        "format",
        "email format",
        "all string formats ignore booleans",
        SUBSET,
        "format email",
    ),
    (
        "format",
        "email format",
        "all string formats ignore nulls",
        SUBSET,
        "format email",
    ),
    (
        "format",
        "email format",
        "invalid email string is only an annotation by default",
        SUBSET,
        "format email",
    ),
    (
        "format",
        "idn-email format",
        "all string formats ignore integers",
        SUBSET,
        "format idn-email",
    ),
    (
        "format",
        "idn-email format",
        "all string formats ignore floats",
        SUBSET,
        "format idn-email",
    ),
    (
        "format",
        "idn-email format",
        "all string formats ignore objects",
        SUBSET,
        "format idn-email",
    ),
    (
        "format",
        "idn-email format",
        "all string formats ignore arrays",
        SUBSET,
        "format idn-email",
    ),
    (
        "format",
        "idn-email format",
        "all string formats ignore booleans",
        SUBSET,
        "format idn-email",
    ),
    (
        "format",
        "idn-email format",
        "all string formats ignore nulls",
        SUBSET,
        "format idn-email",
    ),
    (
        "format",
        "idn-email format",
        "invalid idn-email string is only an annotation by default",
        SUBSET,
        "format idn-email",
    ),
    (
        "format",
        "regex format",
        "all string formats ignore integers",
        SUBSET,
        "format regex",
    ),
    (
        "format",
        "regex format",
        "all string formats ignore floats",
        SUBSET,
        "format regex",
    ),
    (
        "format",
        "regex format",
        "all string formats ignore objects",
        SUBSET,
        "format regex",
    ),
    (
        "format",
        "regex format",
        "all string formats ignore arrays",
        SUBSET,
        "format regex",
    ),
    (
        "format",
        "regex format",
        "all string formats ignore booleans",
        SUBSET,
        "format regex",
    ),
    (
        "format",
        "regex format",
        "all string formats ignore nulls",
        SUBSET,
        "format regex",
    ),
    (
        "format",
        "regex format",
        "invalid regex string is only an annotation by default",
        SUBSET,
        "format regex",
    ),
    (
        "format",
        "ipv4 format",
        "all string formats ignore integers",
        SUBSET,
        "format ipv4",
    ),
    (
        "format",
        "ipv4 format",
        "all string formats ignore floats",
        SUBSET,
        "format ipv4",
    ),
    (
        "format",
        "ipv4 format",
        "all string formats ignore objects",
        SUBSET,
        "format ipv4",
    ),
    (
        "format",
        "ipv4 format",
        "all string formats ignore arrays",
        SUBSET,
        "format ipv4",
    ),
    (
        "format",
        "ipv4 format",
        "all string formats ignore booleans",
        SUBSET,
        "format ipv4",
    ),
    (
        "format",
        "ipv4 format",
        "all string formats ignore nulls",
        SUBSET,
        "format ipv4",
    ),
    (
        "format",
        "ipv4 format",
        "invalid ipv4 string is only an annotation by default",
        SUBSET,
        "format ipv4",
    ),
    (
        "format",
        "ipv6 format",
        "all string formats ignore integers",
        SUBSET,
        "format ipv6",
    ),
    (
        "format",
        "ipv6 format",
        "all string formats ignore floats",
        SUBSET,
        "format ipv6",
    ),
    (
        "format",
        "ipv6 format",
        "all string formats ignore objects",
        SUBSET,
        "format ipv6",
    ),
    (
        "format",
        "ipv6 format",
        "all string formats ignore arrays",
        SUBSET,
        "format ipv6",
    ),
    (
        "format",
        "ipv6 format",
        "all string formats ignore booleans",
        SUBSET,
        "format ipv6",
    ),
    (
        "format",
        "ipv6 format",
        "all string formats ignore nulls",
        SUBSET,
        "format ipv6",
    ),
    (
        "format",
        "ipv6 format",
        "invalid ipv6 string is only an annotation by default",
        SUBSET,
        "format ipv6",
    ),
    (
        "format",
        "idn-hostname format",
        "all string formats ignore integers",
        SUBSET,
        "format idn-hostname",
    ),
    (
        "format",
        "idn-hostname format",
        "all string formats ignore floats",
        SUBSET,
        "format idn-hostname",
    ),
    (
        "format",
        "idn-hostname format",
        "all string formats ignore objects",
        SUBSET,
        "format idn-hostname",
    ),
    (
        "format",
        "idn-hostname format",
        "all string formats ignore arrays",
        SUBSET,
        "format idn-hostname",
    ),
    (
        "format",
        "idn-hostname format",
        "all string formats ignore booleans",
        SUBSET,
        "format idn-hostname",
    ),
    (
        "format",
        "idn-hostname format",
        "all string formats ignore nulls",
        SUBSET,
        "format idn-hostname",
    ),
    (
        "format",
        "idn-hostname format",
        "invalid idn-hostname string is only an annotation by default",
        SUBSET,
        "format idn-hostname",
    ),
    (
        "format",
        "hostname format",
        "all string formats ignore integers",
        SUBSET,
        "format hostname",
    ),
    (
        "format",
        "hostname format",
        "all string formats ignore floats",
        SUBSET,
        "format hostname",
    ),
    (
        "format",
        "hostname format",
        "all string formats ignore objects",
        SUBSET,
        "format hostname",
    ),
    (
        "format",
        "hostname format",
        "all string formats ignore arrays",
        SUBSET,
        "format hostname",
    ),
    (
        "format",
        "hostname format",
        "all string formats ignore booleans",
        SUBSET,
        "format hostname",
    ),
    (
        "format",
        "hostname format",
        "all string formats ignore nulls",
        SUBSET,
        "format hostname",
    ),
    (
        "format",
        "hostname format",
        "invalid hostname string is only an annotation by default",
        SUBSET,
        "format hostname",
    ),
    (
        "format",
        "date format",
        "all string formats ignore floats",
        PROFILE,
        "non-integer number",
    ),
    (
        "format",
        "date-time format",
        "all string formats ignore integers",
        SUBSET,
        "format date-time",
    ),
    (
        "format",
        "date-time format",
        "all string formats ignore floats",
        SUBSET,
        "format date-time",
    ),
    (
        "format",
        "date-time format",
        "all string formats ignore objects",
        SUBSET,
        "format date-time",
    ),
    (
        "format",
        "date-time format",
        "all string formats ignore arrays",
        SUBSET,
        "format date-time",
    ),
    (
        "format",
        "date-time format",
        "all string formats ignore booleans",
        SUBSET,
        "format date-time",
    ),
    (
        "format",
        "date-time format",
        "all string formats ignore nulls",
        SUBSET,
        "format date-time",
    ),
    (
        "format",
        "date-time format",
        "invalid date-time string is only an annotation by default",
        SUBSET,
        "format date-time",
    ),
    (
        "format",
        "time format",
        "all string formats ignore integers",
        SUBSET,
        "format time",
    ),
    (
        "format",
        "time format",
        "all string formats ignore floats",
        SUBSET,
        "format time",
    ),
    (
        "format",
        "time format",
        "all string formats ignore objects",
        SUBSET,
        "format time",
    ),
    (
        "format",
        "time format",
        "all string formats ignore arrays",
        SUBSET,
        "format time",
    ),
    (
        "format",
        "time format",
        "all string formats ignore booleans",
        SUBSET,
        "format time",
    ),
    (
        "format",
        "time format",
        "all string formats ignore nulls",
        SUBSET,
        "format time",
    ),
    (
        "format",
        "time format",
        "invalid time string is only an annotation by default",
        SUBSET,
        "format time",
    ),
    (
        "format",
        "json-pointer format",
        "all string formats ignore integers",
        SUBSET,
        "format json-pointer",
    ),
    (
        "format",
        "json-pointer format",
        "all string formats ignore floats",
        SUBSET,
        "format json-pointer",
    ),
    (
        "format",
        "json-pointer format",
        "all string formats ignore objects",
        SUBSET,
        "format json-pointer",
    ),
    (
        "format",
        "json-pointer format",
        "all string formats ignore arrays",
        SUBSET,
        "format json-pointer",
    ),
    (
        "format",
        "json-pointer format",
        "all string formats ignore booleans",
        SUBSET,
        "format json-pointer",
    ),
    (
        "format",
        "json-pointer format",
        "all string formats ignore nulls",
        SUBSET,
        "format json-pointer",
    ),
    (
        "format",
        "json-pointer format",
        "invalid json-pointer string is only an annotation by default",
        SUBSET,
        "format json-pointer",
    ),
    (
        "format",
        "relative-json-pointer format",
        "all string formats ignore integers",
        SUBSET,
        "format relative-json-pointer",
    ),
    (
        "format",
        "relative-json-pointer format",
        "all string formats ignore floats",
        SUBSET,
        "format relative-json-pointer",
    ),
    (
        "format",
        "relative-json-pointer format",
        "all string formats ignore objects",
        SUBSET,
        "format relative-json-pointer",
    ),
    (
        "format",
        "relative-json-pointer format",
        "all string formats ignore arrays",
        SUBSET,
        "format relative-json-pointer",
    ),
    (
        "format",
        "relative-json-pointer format",
        "all string formats ignore booleans",
        SUBSET,
        "format relative-json-pointer",
    ),
    (
        "format",
        "relative-json-pointer format",
        "all string formats ignore nulls",
        SUBSET,
        "format relative-json-pointer",
    ),
    (
        "format",
        "relative-json-pointer format",
        "invalid relative-json-pointer string is only an annotation by default",
        SUBSET,
        "format relative-json-pointer",
    ),
    (
        "format",
        "iri format",
        "all string formats ignore integers",
        SUBSET,
        "format iri",
    ),
    (
        "format",
        "iri format",
        "all string formats ignore floats",
        SUBSET,
        "format iri",
    ),
    (
        "format",
        "iri format",
        "all string formats ignore objects",
        SUBSET,
        "format iri",
    ),
    (
        "format",
        "iri format",
        "all string formats ignore arrays",
        SUBSET,
        "format iri",
    ),
    (
        "format",
        "iri format",
        "all string formats ignore booleans",
        SUBSET,
        "format iri",
    ),
    (
        "format",
        "iri format",
        "all string formats ignore nulls",
        SUBSET,
        "format iri",
    ),
    (
        "format",
        "iri format",
        "invalid iri string is only an annotation by default",
        SUBSET,
        "format iri",
    ),
    (
        "format",
        "iri-reference format",
        "all string formats ignore integers",
        SUBSET,
        "format iri-reference",
    ),
    (
        "format",
        "iri-reference format",
        "all string formats ignore floats",
        SUBSET,
        "format iri-reference",
    ),
    (
        "format",
        "iri-reference format",
        "all string formats ignore objects",
        SUBSET,
        "format iri-reference",
    ),
    (
        "format",
        "iri-reference format",
        "all string formats ignore arrays",
        SUBSET,
        "format iri-reference",
    ),
    (
        "format",
        "iri-reference format",
        "all string formats ignore booleans",
        SUBSET,
        "format iri-reference",
    ),
    (
        "format",
        "iri-reference format",
        "all string formats ignore nulls",
        SUBSET,
        "format iri-reference",
    ),
    (
        "format",
        "iri-reference format",
        "invalid iri-reference string is only an annotation by default",
        SUBSET,
        "format iri-reference",
    ),
    (
        "format",
        "uri format",
        "all string formats ignore integers",
        SUBSET,
        "format uri",
    ),
    (
        "format",
        "uri format",
        "all string formats ignore floats",
        SUBSET,
        "format uri",
    ),
    (
        "format",
        "uri format",
        "all string formats ignore objects",
        SUBSET,
        "format uri",
    ),
    (
        "format",
        "uri format",
        "all string formats ignore arrays",
        SUBSET,
        "format uri",
    ),
    (
        "format",
        "uri format",
        "all string formats ignore booleans",
        SUBSET,
        "format uri",
    ),
    (
        "format",
        "uri format",
        "all string formats ignore nulls",
        SUBSET,
        "format uri",
    ),
    (
        "format",
        "uri format",
        "invalid uri string is only an annotation by default",
        SUBSET,
        "format uri",
    ),
    (
        "format",
        "uri-reference format",
        "all string formats ignore integers",
        SUBSET,
        "format uri-reference",
    ),
    (
        "format",
        "uri-reference format",
        "all string formats ignore floats",
        SUBSET,
        "format uri-reference",
    ),
    (
        "format",
        "uri-reference format",
        "all string formats ignore objects",
        SUBSET,
        "format uri-reference",
    ),
    (
        "format",
        "uri-reference format",
        "all string formats ignore arrays",
        SUBSET,
        "format uri-reference",
    ),
    (
        "format",
        "uri-reference format",
        "all string formats ignore booleans",
        SUBSET,
        "format uri-reference",
    ),
    (
        "format",
        "uri-reference format",
        "all string formats ignore nulls",
        SUBSET,
        "format uri-reference",
    ),
    (
        "format",
        "uri-reference format",
        "invalid uri-reference string is only an annotation by default",
        SUBSET,
        "format uri-reference",
    ),
    (
        "format",
        "uri-template format",
        "all string formats ignore integers",
        SUBSET,
        "format uri-template",
    ),
    (
        "format",
        "uri-template format",
        "all string formats ignore floats",
        SUBSET,
        "format uri-template",
    ),
    (
        "format",
        "uri-template format",
        "all string formats ignore objects",
        SUBSET,
        "format uri-template",
    ),
    (
        "format",
        "uri-template format",
        "all string formats ignore arrays",
        SUBSET,
        "format uri-template",
    ),
    (
        "format",
        "uri-template format",
        "all string formats ignore booleans",
        SUBSET,
        "format uri-template",
    ),
    (
        "format",
        "uri-template format",
        "all string formats ignore nulls",
        SUBSET,
        "format uri-template",
    ),
    (
        "format",
        "uri-template format",
        "invalid uri-template string is only an annotation by default",
        SUBSET,
        "format uri-template",
    ),
    (
        "format",
        "uuid format",
        "all string formats ignore integers",
        SUBSET,
        "format uuid",
    ),
    (
        "format",
        "uuid format",
        "all string formats ignore floats",
        SUBSET,
        "format uuid",
    ),
    (
        "format",
        "uuid format",
        "all string formats ignore objects",
        SUBSET,
        "format uuid",
    ),
    (
        "format",
        "uuid format",
        "all string formats ignore arrays",
        SUBSET,
        "format uuid",
    ),
    (
        "format",
        "uuid format",
        "all string formats ignore booleans",
        SUBSET,
        "format uuid",
    ),
    (
        "format",
        "uuid format",
        "all string formats ignore nulls",
        SUBSET,
        "format uuid",
    ),
    (
        "format",
        "uuid format",
        "invalid uuid string is only an annotation by default",
        SUBSET,
        "format uuid",
    ),
    (
        "format",
        "duration format",
        "all string formats ignore integers",
        SUBSET,
        "format duration",
    ),
    (
        "format",
        "duration format",
        "all string formats ignore floats",
        SUBSET,
        "format duration",
    ),
    (
        "format",
        "duration format",
        "all string formats ignore objects",
        SUBSET,
        "format duration",
    ),
    (
        "format",
        "duration format",
        "all string formats ignore arrays",
        SUBSET,
        "format duration",
    ),
    (
        "format",
        "duration format",
        "all string formats ignore booleans",
        SUBSET,
        "format duration",
    ),
    (
        "format",
        "duration format",
        "all string formats ignore nulls",
        SUBSET,
        "format duration",
    ),
    (
        "format",
        "duration format",
        "invalid duration string is only an annotation by default",
        SUBSET,
        "format duration",
    ),
    (
        "items",
        "items and subitems",
        "valid items",
        SUBSET,
        "keyword $defs",
    ),
    (
        "items",
        "items and subitems",
        "too many items",
        SUBSET,
        "keyword $defs",
    ),
    (
        "items",
        "items and subitems",
        "too many sub-items",
        SUBSET,
        "keyword $defs",
    ),
    (
        "items",
        "items and subitems",
        "wrong item",
        SUBSET,
        "keyword $defs",
    ),
    (
        "items",
        "items and subitems",
        "wrong sub-item",
        SUBSET,
        "keyword $defs",
    ),
    (
        "items",
        "items and subitems",
        "fewer items is valid",
        SUBSET,
        "keyword $defs",
    ),
    (
        "items",
        "prefixItems with no additional items allowed",
        "empty array",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "items",
        "prefixItems with no additional items allowed",
        "fewer number of items present (1)",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "items",
        "prefixItems with no additional items allowed",
        "fewer number of items present (2)",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "items",
        "prefixItems with no additional items allowed",
        "equal number of items present",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "items",
        "prefixItems with no additional items allowed",
        "additional items are not permitted",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "items",
        "items does not look in applicators, valid case",
        "prefixItems in allOf does not constrain items, invalid case",
        SUBSET,
        "keyword allOf",
    ),
    (
        "items",
        "items does not look in applicators, valid case",
        "prefixItems in allOf does not constrain items, valid case",
        SUBSET,
        "keyword allOf",
    ),
    (
        "items",
        "prefixItems validation adjusts the starting index for items",
        "valid items",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "items",
        "prefixItems validation adjusts the starting index for items",
        "wrong type of second item",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "items",
        "items with heterogeneous array",
        "heterogeneous invalid instance",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "items",
        "items with heterogeneous array",
        "valid instance",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "maxItems",
        "maxItems validation with a decimal",
        "shorter is valid",
        SUBSET,
        "non-integer maxItems",
    ),
    (
        "maxItems",
        "maxItems validation with a decimal",
        "too long is invalid",
        SUBSET,
        "non-integer maxItems",
    ),
    (
        "maxLength",
        "maxLength validation with a decimal",
        "shorter is valid",
        SUBSET,
        "non-integer maxLength",
    ),
    (
        "maxLength",
        "maxLength validation with a decimal",
        "too long is invalid",
        SUBSET,
        "non-integer maxLength",
    ),
    (
        "maxProperties",
        "maxProperties validation with a decimal",
        "shorter is valid",
        SUBSET,
        "non-integer maxProperties",
    ),
    (
        "maxProperties",
        "maxProperties validation with a decimal",
        "too long is invalid",
        SUBSET,
        "non-integer maxProperties",
    ),
    (
        "maximum",
        "maximum validation",
        "below the maximum is valid",
        SUBSET,
        "non-integer maximum",
    ),
    (
        "maximum",
        "maximum validation",
        "boundary point is valid",
        SUBSET,
        "non-integer maximum",
    ),
    (
        "maximum",
        "maximum validation",
        "above the maximum is invalid",
        SUBSET,
        "non-integer maximum",
    ),
    (
        "maximum",
        "maximum validation",
        "ignores non-numbers",
        SUBSET,
        "non-integer maximum",
    ),
    (
        "maximum",
        "maximum validation with unsigned integer",
        "below the maximum is valid",
        PROFILE,
        "non-integer number",
    ),
    (
        "maximum",
        "maximum validation with unsigned integer",
        "boundary point float is valid",
        PROFILE,
        "non-integer number",
    ),
    (
        "maximum",
        "maximum validation with unsigned integer",
        "above the maximum is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "minItems",
        "minItems validation with a decimal",
        "longer is valid",
        SUBSET,
        "non-integer minItems",
    ),
    (
        "minItems",
        "minItems validation with a decimal",
        "too short is invalid",
        SUBSET,
        "non-integer minItems",
    ),
    (
        "minLength",
        "minLength validation with a decimal",
        "longer is valid",
        SUBSET,
        "non-integer minLength",
    ),
    (
        "minLength",
        "minLength validation with a decimal",
        "too short is invalid",
        SUBSET,
        "non-integer minLength",
    ),
    (
        "minProperties",
        "minProperties validation with a decimal",
        "longer is valid",
        SUBSET,
        "non-integer minProperties",
    ),
    (
        "minProperties",
        "minProperties validation with a decimal",
        "too short is invalid",
        SUBSET,
        "non-integer minProperties",
    ),
    (
        "minimum",
        "minimum validation",
        "above the minimum is valid",
        SUBSET,
        "non-integer minimum",
    ),
    (
        "minimum",
        "minimum validation",
        "boundary point is valid",
        SUBSET,
        "non-integer minimum",
    ),
    (
        "minimum",
        "minimum validation",
        "below the minimum is invalid",
        SUBSET,
        "non-integer minimum",
    ),
    (
        "minimum",
        "minimum validation",
        "ignores non-numbers",
        SUBSET,
        "non-integer minimum",
    ),
    (
        "minimum",
        "minimum validation with signed integer",
        "boundary point with float is valid",
        PROFILE,
        "non-integer number",
    ),
    (
        "minimum",
        "minimum validation with signed integer",
        "float below the minimum is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "pattern",
        "pattern validation",
        "ignores floats",
        PROFILE,
        "non-integer number",
    ),
    (
        "pattern",
        "pattern with Unicode property escape requires unicode mode",
        "ASCII letters match",
        SUBSET,
        "pattern escape \\p{Letter}",
    ),
    (
        "pattern",
        "pattern with Unicode property escape requires unicode mode",
        "Non-ASCII letters match",
        SUBSET,
        "pattern escape \\p{Letter}",
    ),
    (
        "pattern",
        "pattern with Unicode property escape requires unicode mode",
        "Digits do not match",
        SUBSET,
        "pattern escape \\p{Letter}",
    ),
    (
        "properties",
        "properties, patternProperties, additionalProperties interaction",
        "property validates property",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "properties",
        "properties, patternProperties, additionalProperties interaction",
        "property invalidates property",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "properties",
        "properties, patternProperties, additionalProperties interaction",
        "patternProperty invalidates property",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "properties",
        "properties, patternProperties, additionalProperties interaction",
        "patternProperty validates nonproperty",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "properties",
        "properties, patternProperties, additionalProperties interaction",
        "patternProperty invalidates nonproperty",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "properties",
        "properties, patternProperties, additionalProperties interaction",
        "additionalProperty ignores property",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "properties",
        "properties, patternProperties, additionalProperties interaction",
        "additionalProperty validates others",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "properties",
        "properties, patternProperties, additionalProperties interaction",
        "additionalProperty invalidates others",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "type",
        "integer type matches integers",
        "a float with zero fractional part is an integer",
        PROFILE,
        "non-integer number",
    ),
    (
        "type",
        "integer type matches integers",
        "a float is not an integer",
        PROFILE,
        "non-integer number",
    ),
    (
        "type",
        "number type matches numbers",
        "a float with zero fractional part is a number (and an integer)",
        PROFILE,
        "non-integer number",
    ),
    (
        "type",
        "number type matches numbers",
        "a float is a number",
        PROFILE,
        "non-integer number",
    ),
    (
        "type",
        "string type matches strings",
        "a float is not a string",
        PROFILE,
        "non-integer number",
    ),
    (
        "type",
        "object type matches objects",
        "a float is not an object",
        PROFILE,
        "non-integer number",
    ),
    (
        "type",
        "array type matches arrays",
        "a float is not an array",
        PROFILE,
        "non-integer number",
    ),
    (
        "type",
        "boolean type matches booleans",
        "a float is not a boolean",
        PROFILE,
        "non-integer number",
    ),
    (
        "type",
        "null type matches only the null object",
        "a float is not null",
        PROFILE,
        "non-integer number",
    ),
    (
        "type",
        "multiple types can be specified in an array",
        "a float is invalid",
        PROFILE,
        "non-integer number",
    ),
    (
        "uniqueItems",
        "uniqueItems validation",
        "numbers are unique if mathematically unequal",
        PROFILE,
        "non-integer number",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items",
        "[false, true] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items",
        "[true, false] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items",
        "[false, false] from items array is not valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items",
        "[true, true] from items array is not valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items",
        "unique array extended from [false, true] is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items",
        "unique array extended from [true, false] is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items",
        "non-unique array extended from [false, true] is not valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items",
        "non-unique array extended from [true, false] is not valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items and additionalItems=false",
        "[false, true] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items and additionalItems=false",
        "[true, false] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items and additionalItems=false",
        "[false, false] from items array is not valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items and additionalItems=false",
        "[true, true] from items array is not valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems with an array of items and additionalItems=false",
        "extra items are invalid even if unique",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false validation",
        "numbers are unique if mathematically unequal",
        PROFILE,
        "non-integer number",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items",
        "[false, true] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items",
        "[true, false] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items",
        "[false, false] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items",
        "[true, true] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items",
        "unique array extended from [false, true] is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items",
        "unique array extended from [true, false] is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items",
        "non-unique array extended from [false, true] is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items",
        "non-unique array extended from [true, false] is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items and additionalItems=false",
        "[false, true] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items and additionalItems=false",
        "[true, false] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items and additionalItems=false",
        "[false, false] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items and additionalItems=false",
        "[true, true] from items array is valid",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "uniqueItems",
        "uniqueItems=false with an array of items and additionalItems=false",
        "extra items are invalid even if unique",
        SUBSET,
        "keyword prefixItems",
    ),
    (
        "optional/format/date",
        "validation of date strings",
        "all string formats ignore floats",
        PROFILE,
        "non-integer number",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 regex converts \\t to horizontal tab",
        "does not match",
        SUBSET,
        "pattern escape \\t",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 regex converts \\t to horizontal tab",
        "matches",
        SUBSET,
        "pattern escape \\t",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 regex escapes control codes with \\c and upper letter",
        "does not match",
        SUBSET,
        "pattern escape \\c",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 regex escapes control codes with \\c and upper letter",
        "matches",
        SUBSET,
        "pattern escape \\c",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 regex escapes control codes with \\c and lower letter",
        "does not match",
        SUBSET,
        "pattern escape \\c",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 regex escapes control codes with \\c and lower letter",
        "matches",
        SUBSET,
        "pattern escape \\c",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\D matches everything but ascii digits",
        "ASCII zero does not match",
        SUBSET,
        "pattern escape \\D",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\D matches everything but ascii digits",
        "NKO DIGIT ZERO matches (unlike e.g. Python)",
        SUBSET,
        "pattern escape \\D",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\D matches everything but ascii digits",
        "NKO DIGIT ZERO (as \\u escape) matches",
        SUBSET,
        "pattern escape \\D",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\w matches ascii letters only",
        "ASCII 'a' matches",
        SUBSET,
        "pattern escape \\w",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\w matches ascii letters only",
        "latin-1 e-acute does not match (unlike e.g. Python)",
        SUBSET,
        "pattern escape \\w",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\W matches everything but ascii letters",
        "ASCII 'a' does not match",
        SUBSET,
        "pattern escape \\W",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\W matches everything but ascii letters",
        "latin-1 e-acute matches (unlike e.g. Python)",
        SUBSET,
        "pattern escape \\W",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\s matches whitespace",
        "ASCII space matches",
        SUBSET,
        "pattern escape \\s",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\s matches whitespace",
        "Character tabulation matches",
        SUBSET,
        "pattern escape \\s",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\s matches whitespace",
        "Line tabulation matches",
        SUBSET,
        "pattern escape \\s",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\s matches whitespace",
        "Form feed matches",
        SUBSET,
        "pattern escape \\s",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\s matches whitespace",
        "latin-1 non-breaking-space matches",
        SUBSET,
        "pattern escape \\s",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\s matches whitespace",
        "zero-width whitespace matches",
        SUBSET,
        "pattern escape \\s",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\s matches whitespace",
        "line feed matches (line terminator)",
        SUBSET,
        "pattern escape \\s",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\s matches whitespace",
        "paragraph separator matches (line terminator)",
        SUBSET,
        "pattern escape \\s",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\s matches whitespace",
        "EM SPACE matches (Space_Separator)",
        SUBSET,
        "pattern escape \\s",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\s matches whitespace",
        "Non-whitespace control does not match",
        SUBSET,
        "pattern escape \\s",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\s matches whitespace",
        "Non-whitespace does not match",
        SUBSET,
        "pattern escape \\s",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\S matches everything but whitespace",
        "ASCII space does not match",
        SUBSET,
        "pattern escape \\S",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\S matches everything but whitespace",
        "Character tabulation does not match",
        SUBSET,
        "pattern escape \\S",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\S matches everything but whitespace",
        "Line tabulation does not match",
        SUBSET,
        "pattern escape \\S",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\S matches everything but whitespace",
        "Form feed does not match",
        SUBSET,
        "pattern escape \\S",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\S matches everything but whitespace",
        "latin-1 non-breaking-space does not match",
        SUBSET,
        "pattern escape \\S",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\S matches everything but whitespace",
        "zero-width whitespace does not match",
        SUBSET,
        "pattern escape \\S",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\S matches everything but whitespace",
        "line feed does not match (line terminator)",
        SUBSET,
        "pattern escape \\S",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\S matches everything but whitespace",
        "paragraph separator does not match (line terminator)",
        SUBSET,
        "pattern escape \\S",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\S matches everything but whitespace",
        "EM SPACE does not match (Space_Separator)",
        SUBSET,
        "pattern escape \\S",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\S matches everything but whitespace",
        "Non-whitespace control matches",
        SUBSET,
        "pattern escape \\S",
    ),
    (
        "optional/ecmascript-regex",
        "ECMA 262 \\S matches everything but whitespace",
        "Non-whitespace matches",
        SUBSET,
        "pattern escape \\S",
    ),
    (
        "optional/ecmascript-regex",
        "patterns always use unicode semantics with pattern",
        "ascii character in json string",
        SUBSET,
        "pattern escape \\p{Letter}",
    ),
    (
        "optional/ecmascript-regex",
        "patterns always use unicode semantics with pattern",
        "literal unicode character in json string",
        SUBSET,
        "pattern escape \\p{Letter}",
    ),
    (
        "optional/ecmascript-regex",
        "patterns always use unicode semantics with pattern",
        "unicode character in hex format in string",
        SUBSET,
        "pattern escape \\p{Letter}",
    ),
    (
        "optional/ecmascript-regex",
        "patterns always use unicode semantics with pattern",
        "unicode matching is case-sensitive",
        SUBSET,
        "pattern escape \\p{Letter}",
    ),
    (
        "optional/ecmascript-regex",
        "\\w in patterns matches [A-Za-z0-9_], not unicode letters",
        "ascii character in json string",
        SUBSET,
        "pattern escape \\w",
    ),
    (
        "optional/ecmascript-regex",
        "\\w in patterns matches [A-Za-z0-9_], not unicode letters",
        "literal unicode character in json string",
        SUBSET,
        "pattern escape \\w",
    ),
    (
        "optional/ecmascript-regex",
        "\\w in patterns matches [A-Za-z0-9_], not unicode letters",
        "unicode character in hex format in string",
        SUBSET,
        "pattern escape \\w",
    ),
    (
        "optional/ecmascript-regex",
        "\\w in patterns matches [A-Za-z0-9_], not unicode letters",
        "unicode matching is case-sensitive",
        SUBSET,
        "pattern escape \\w",
    ),
    (
        "optional/ecmascript-regex",
        "pattern with non-ASCII digits",
        "ascii digits",
        SUBSET,
        "pattern escape \\p{digit}",
    ),
    (
        "optional/ecmascript-regex",
        "pattern with non-ASCII digits",
        "ascii non-digits",
        SUBSET,
        "pattern escape \\p{digit}",
    ),
    (
        "optional/ecmascript-regex",
        "pattern with non-ASCII digits",
        "non-ascii digits (BENGALI DIGIT FOUR, BENGALI DIGIT TWO)",
        SUBSET,
        "pattern escape \\p{digit}",
    ),
    (
        "optional/ecmascript-regex",
        "patterns always use unicode semantics with patternProperties",
        "ascii character in json string",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "patterns always use unicode semantics with patternProperties",
        "literal unicode character in json string",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "patterns always use unicode semantics with patternProperties",
        "unicode character in hex format in string",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "patterns always use unicode semantics with patternProperties",
        "unicode matching is case-sensitive",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "\\w in patternProperties matches [A-Za-z0-9_], not unicode letters",
        "ascii character in json string",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "\\w in patternProperties matches [A-Za-z0-9_], not unicode letters",
        "literal unicode character in json string",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "\\w in patternProperties matches [A-Za-z0-9_], not unicode letters",
        "unicode character in hex format in string",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "\\w in patternProperties matches [A-Za-z0-9_], not unicode letters",
        "unicode matching is case-sensitive",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "patternProperties with ASCII ranges",
        "literal unicode character in json string",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "patternProperties with ASCII ranges",
        "unicode character in hex format in string",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "patternProperties with ASCII ranges",
        "ascii characters match",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "\\d in patternProperties matches [0-9], not unicode digits",
        "ascii digits",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "\\d in patternProperties matches [0-9], not unicode digits",
        "ascii non-digits",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "\\d in patternProperties matches [0-9], not unicode digits",
        "non-ascii digits (BENGALI DIGIT FOUR, BENGALI DIGIT TWO)",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "patternProperties with non-ASCII digits",
        "ascii digits",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "patternProperties with non-ASCII digits",
        "ascii non-digits",
        SUBSET,
        "keyword patternProperties",
    ),
    (
        "optional/ecmascript-regex",
        "patternProperties with non-ASCII digits",
        "non-ascii digits (BENGALI DIGIT FOUR, BENGALI DIGIT TWO)",
        SUBSET,
        "keyword patternProperties",
    ),
];

/// The keywords a schema uses at schema positions, descending through its applicators.
fn keywords(schema: &Value, found: &mut BTreeSet<String>) {
    let Some(object) = schema.as_object() else {
        return;
    };
    for (keyword, value) in object {
        found.insert(keyword.clone());
        match keyword.as_str() {
            "properties" => {
                for subschema in value
                    .as_object()
                    .into_iter()
                    .flat_map(|members| members.values())
                {
                    keywords(subschema, found);
                }
            }
            "items" | "additionalProperties" => keywords(value, found),
            _ => {}
        }
    }
}

/// Whether `keyword` constrains values of `instance`'s type.
fn constrains(keyword: &str, instance: &Value) -> bool {
    match keyword {
        "type" | "enum" | "const" => true,
        "minimum" | "maximum" => instance.is_number(),
        "minLength" | "maxLength" | "pattern" | "format" => instance.is_string(),
        "items" | "minItems" | "maxItems" | "uniqueItems" => instance.is_array(),
        "properties" | "required" | "additionalProperties" | "minProperties" | "maxProperties" => {
            instance.is_object()
        }
        _ => false,
    }
}

/// The supported keywords that reach a value of their type. The walk follows the positions the
/// instance meets: `properties` members meet the object member of the same name, `items` meets
/// every element, and `additionalProperties` meets every member `properties` does not name.
fn reached(schema: &Value, instance: &Value, found: &mut BTreeSet<String>) {
    let Some(object) = schema.as_object() else {
        return;
    };
    for keyword in object.keys() {
        if SUPPORTED.contains(&keyword.as_str()) && constrains(keyword, instance) {
            found.insert(keyword.clone());
        }
    }
    if let Some(members) = instance.as_object() {
        let named = object.get("properties").and_then(Value::as_object);
        for (name, value) in members {
            match named.and_then(|properties| properties.get(name)) {
                Some(subschema) => reached(subschema, value, found),
                None => {
                    if let Some(additional) = object.get("additionalProperties") {
                        reached(additional, value, found);
                    }
                }
            }
        }
    }
    if let (Some(items), Some(elements)) = (object.get("items"), instance.as_array()) {
        for element in elements {
            reached(items, element, found);
        }
    }
}

/// `schema` with every occurrence of `keyword` removed at the schema positions.
fn without(schema: &Value, keyword: &str) -> Value {
    let Some(object) = schema.as_object() else {
        return schema.clone();
    };
    let mut reduced = Map::new();
    for (name, value) in object {
        if name == keyword {
            continue;
        }
        let value = match name.as_str() {
            "properties" => value.as_object().map_or_else(
                || value.clone(),
                |members| {
                    Value::Object(
                        members
                            .iter()
                            .map(|(member, subschema)| {
                                (member.clone(), without(subschema, keyword))
                            })
                            .collect(),
                    )
                },
            ),
            "items" | "additionalProperties" => without(value, keyword),
            _ => value.clone(),
        };
        reduced.insert(name.clone(), value);
    }
    Value::Object(reduced)
}

/// The keywords one run case counts for, in the direction `valid` names.
///
/// A valid case counts for each supported keyword that reaches a value of its type. An invalid
/// case counts for each supported keyword whose removal leaves a schema that still compiles and
/// accepts the instance.
fn credits(schema: &Value, instance: &Value, valid: bool) -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    if valid {
        reached(schema, instance, &mut found);
        return found;
    }
    keywords(schema, &mut found);
    found
        .into_iter()
        .filter(|keyword| SUPPORTED.contains(&keyword.as_str()))
        .filter(|keyword| {
            CompiledSchema::compile(&without(schema, keyword))
                .is_ok_and(|reduced| reduced.validate(instance).is_ok())
        })
        .collect()
}

/// Adds the synthetic root `$id`, the only change the test may make to a case's schema.
fn with_id(mut schema: Value) -> Value {
    if let Some(root) = schema.as_object_mut() {
        root.entry("$id")
            .or_insert_with(|| json!("urn:docchain:test-suite"));
    }
    schema
}

/// How one case ran: its class, and for a run case, the strict-parsed instance and its result.
enum Outcome {
    Run { instance: Value, valid: bool },
    Excluded(Class),
    CompileFailed(DomainError),
}

fn run(compiled: &Result<CompiledSchema, DomainError>, data: &Value) -> Outcome {
    match compiled {
        Err(DomainError::UnsupportedSchema) => Outcome::Excluded(Class::OutsideSubset),
        Err(other) => Outcome::CompileFailed(other.clone()),
        Ok(compiled) => {
            let bytes = serde_json::to_vec(data).expect("instance bytes");
            match parse_document(&bytes) {
                Err(_) => Outcome::Excluded(Class::OutsideProfile),
                Ok(document) => Outcome::Run {
                    valid: compiled.validate(document.value()).is_ok(),
                    instance: document.value().clone(),
                },
            }
        }
    }
}

/// For each keyword, the cases that count for it: (valid, invalid).
type Coverage = BTreeMap<String, (Vec<String>, Vec<String>)>;

fn record(coverage: &mut Coverage, keywords: &BTreeSet<String>, valid: bool, case: &str) {
    for keyword in keywords {
        let entry = coverage.entry(keyword.clone()).or_default();
        if valid {
            entry.0.push(case.to_owned());
        } else {
            entry.1.push(case.to_owned());
        }
    }
}

fn covers(coverage: &Coverage, keyword: &str, valid: bool) -> bool {
    coverage
        .get(keyword)
        .is_some_and(|(valid_cases, invalid_cases)| {
            !if valid { valid_cases } else { invalid_cases }.is_empty()
        })
}

/// Reads the gap files: each is `<keyword>.json` for a supported keyword, in the suite's format.
fn gap_files() -> Vec<(String, String, Vec<Value>)> {
    let mut files = std::fs::read_dir(format!("{GAP_CASES}{GAP_DIRECTORY}"))
        .expect("gap-case directory")
        .map(|entry| entry.expect("gap-case entry").file_name())
        .map(|name| name.into_string().expect("UTF-8 gap-case file name"))
        .collect::<Vec<_>>();
    files.sort();
    files
        .into_iter()
        .map(|name| {
            let keyword = name
                .strip_suffix(".json")
                .unwrap_or_else(|| panic!("{name}: a gap file is named <keyword>.json"))
                .to_owned();
            let text = std::fs::read_to_string(format!("{GAP_CASES}{GAP_DIRECTORY}/{name}"))
                .expect("gap-case file");
            let groups: Vec<Value> = serde_json::from_str(&text).expect("gap-case JSON");
            (format!("{GAP_DIRECTORY}/{name}"), keyword, groups)
        })
        .collect()
}

#[test]
fn official_cases_match_or_are_listed() {
    let mut listed = BTreeMap::new();
    for &(file, group, case, class, reason) in EXCLUDED {
        assert!(
            !reason.is_empty(),
            "{file} / {group} / {case} needs a reason"
        );
        assert!(
            listed.insert((file, group, case), class).is_none(),
            "{file} / {group} / {case} is listed twice"
        );
    }

    let mut seen = BTreeSet::new();
    let mut problems = Vec::new();
    let mut counts = BTreeMap::<&str, usize>::new();
    let mut coverage = Coverage::new();
    let suite = FILES.map(|file| {
        let text = std::fs::read_to_string(format!("{SUITE}{file}.json")).expect("suite file");
        let groups: Vec<Value> = serde_json::from_str(&text).expect("suite JSON");
        (file, groups)
    });
    for (file, groups) in &suite {
        let file = *file;
        for group in groups {
            let group_name = group["description"].as_str().expect("group description");
            let schema = with_id(group["schema"].clone());
            let compiled = CompiledSchema::compile(&schema);
            for case in group["tests"].as_array().expect("group cases") {
                let case_name = case["description"].as_str().expect("case description");
                let key = (file, group_name, case_name);
                assert!(
                    seen.insert(key),
                    "{file} / {group_name} / {case_name} is not unique"
                );
                let mut expected = case["valid"].as_bool().expect("expected validity");
                if key == ASSERTED_FORMAT {
                    expected = false;
                }
                let outcome = run(&compiled, &case["data"]);
                let class = match &outcome {
                    Outcome::Run { .. } => Class::Run,
                    Outcome::Excluded(class) => *class,
                    Outcome::CompileFailed(other) => {
                        problems.push(format!(
                            "{file} / {group_name}: compile failed as {other:?}"
                        ));
                        continue;
                    }
                };
                *counts
                    .entry(match class {
                        Class::Run => "run",
                        Class::OutsideSubset => "outside the subset",
                        Class::OutsideProfile => "outside the strict profile",
                    })
                    .or_default() += 1;
                match (outcome, listed.get(&key)) {
                    (Outcome::Run { instance, valid }, None) => {
                        if valid != expected {
                            problems.push(format!(
                                "{file} / {group_name} / {case_name}: expected valid = {expected}"
                            ));
                        }
                        record(
                            &mut coverage,
                            &credits(&schema, &instance, expected),
                            expected,
                            &format!("{file} / {group_name} / {case_name}"),
                        );
                    }
                    (Outcome::Run { .. }, Some(listed)) => problems.push(format!(
                        "{file} / {group_name} / {case_name}: runs but is listed as {listed:?}"
                    )),
                    (_, Some(listed)) if class == *listed => {}
                    (_, listed) => problems.push(format!(
                        "{file} / {group_name} / {case_name}: {class:?} but listed as {listed:?}"
                    )),
                }
            }
        }
    }

    for key in listed.keys().filter(|key| !seen.contains(*key)) {
        problems.push(format!("listed case not in the suite: {key:?}"));
    }
    assert!(
        seen.contains(&ASSERTED_FORMAT),
        "the asserted-format case is missing"
    );
    let maximum_valid = coverage
        .get("maximum")
        .map(|(valid, _)| valid.clone())
        .unwrap_or_default();
    if maximum_valid != [MAXIMUM_VALID_SOURCE] {
        problems.push(format!(
            "maximum: suite valid-direction sources are {maximum_valid:?}, expected only \
             {MAXIMUM_VALID_SOURCE:?}; review the gap files"
        ));
    }

    // Gap cases: each must run, match, and count only for directions the suite lacks.
    let mut gap_coverage = Coverage::new();
    for (path, file_keyword, groups) in gap_files() {
        if !SUPPORTED.contains(&file_keyword.as_str()) {
            problems.push(format!("{path}: not a supported keyword"));
        }
        for group in &groups {
            let group_name = group["description"].as_str().expect("group description");
            if group["schema"]["$schema"] != json!("https://json-schema.org/draft/2020-12/schema") {
                problems.push(format!(
                    "{path} / {group_name}: needs the Draft 2020-12 $schema"
                ));
            }
            let schema = with_id(group["schema"].clone());
            let compiled = CompiledSchema::compile(&schema);
            for case in group["tests"].as_array().expect("group cases") {
                let case_name = case["description"].as_str().unwrap_or_default();
                let name = format!("{path} / {group_name} / {case_name}");
                let members = case
                    .as_object()
                    .map(|members| members.keys().map(String::as_str).collect::<Vec<_>>())
                    .unwrap_or_default();
                if members != ["data", "description", "valid"] {
                    problems.push(format!("{name}: members are {members:?}"));
                    continue;
                }
                let expected = case["valid"].as_bool().expect("expected validity");
                *counts.entry("gap cases").or_default() += 1;
                let Outcome::Run { instance, valid } = run(&compiled, &case["data"]) else {
                    problems.push(format!("{name}: does not run"));
                    continue;
                };
                if valid != expected {
                    problems.push(format!("{name}: expected valid = {expected}"));
                }
                let counted = credits(&schema, &instance, expected);
                for keyword in &counted {
                    if covers(&coverage, keyword, expected) {
                        problems.push(format!(
                            "{name}: counts for {keyword} (valid = {expected}), which the suite covers"
                        ));
                    }
                }
                if !counted.contains(&file_keyword) {
                    problems.push(format!(
                        "{name}: counts for no missing direction of {file_keyword}"
                    ));
                }
                record(&mut gap_coverage, &counted, expected, &name);
            }
        }
    }

    for keyword in SUPPORTED {
        let observed = [true, false].map(|valid| {
            covers(&coverage, keyword, valid) || covers(&gap_coverage, keyword, valid)
        });
        if observed != [true, true] {
            problems.push(format!(
                "{keyword}: run-case coverage (valid, invalid) is {observed:?}"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "{counts:?}\ngap coverage: {gap_coverage:?}\n{}",
        problems.join("\n")
    );
}

/// Runs one synthetic case through the same coverage function, after checking its expectation.
fn synthetic_credits(schema: Value, data: &Value, valid: bool) -> BTreeSet<String> {
    let schema = with_id(schema);
    let compiled = CompiledSchema::compile(&schema);
    let Outcome::Run {
        instance,
        valid: observed,
    } = run(&compiled, data)
    else {
        panic!("{schema} with {data} does not run");
    };
    assert_eq!(observed, valid, "{schema} with {data}");
    credits(&schema, &instance, valid)
}

fn names(keywords: &[&str]) -> BTreeSet<String> {
    keywords
        .iter()
        .map(|keyword| (*keyword).to_owned())
        .collect()
}

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

#[test]
fn invalid_cases_credit_only_the_deciding_keyword() {
    assert_eq!(
        synthetic_credits(
            json!({"$schema": DRAFT, "type": "string", "maximum": 300}),
            &json!(5),
            false
        ),
        names(&["type"])
    );
    assert_eq!(
        synthetic_credits(
            json!({"$schema": DRAFT, "maximum": 300}),
            &json!(301),
            false
        ),
        names(&["maximum"])
    );
}

#[test]
fn valid_cases_credit_only_keywords_that_reach_their_type() {
    let cases = [
        (
            json!({"$schema": DRAFT, "type": "string", "maximum": 300}),
            json!("x"),
            &["type"][..],
        ),
        (
            json!({"$schema": DRAFT, "maximum": 300}),
            json!(300),
            &["maximum"][..],
        ),
        (
            json!({"$schema": DRAFT, "properties": {"a": {"maximum": 3}}}),
            json!({"a": 2}),
            &["maximum", "properties"][..],
        ),
        (
            json!({"$schema": DRAFT, "properties": {"a": {"maximum": 3}}}),
            json!({"a": "x"}),
            &["properties"][..],
        ),
        // A vacuous credit: no member of the instance meets `properties`' subschemas.
        (
            json!({"$schema": DRAFT, "properties": {"a": {"maximum": 3}}}),
            json!({"b": 2}),
            &["properties"][..],
        ),
        // A vacuous credit: the empty array has no element for `items` to meet.
        (
            json!({"$schema": DRAFT, "items": {"minLength": 1}}),
            json!([]),
            &["items"][..],
        ),
        (
            json!({"$schema": DRAFT, "items": {"minLength": 1}}),
            json!(["a"]),
            &["items", "minLength"][..],
        ),
        (
            json!({
                "$schema": DRAFT,
                "properties": {"a": true},
                "additionalProperties": {"maximum": 3}
            }),
            json!({"b": 2}),
            &["additionalProperties", "maximum", "properties"][..],
        ),
        (
            json!({
                "$schema": DRAFT,
                "properties": {"a": true},
                "additionalProperties": {"maximum": 3}
            }),
            json!({"a": 2}),
            &["additionalProperties", "properties"][..],
        ),
    ];
    for (schema, data, expected) in cases {
        let description = format!("{schema} with {data}");
        assert_eq!(
            synthetic_credits(schema, &data, true),
            names(expected),
            "{description}"
        );
    }
}
