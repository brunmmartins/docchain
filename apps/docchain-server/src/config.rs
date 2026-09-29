//! Typed composition-root configuration.

use std::{
    collections::HashMap,
    env,
    ffi::{OsStr, OsString},
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use thiserror::Error;

/// A secret value whose debug representation never reveals the value.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret(redacted)")
    }
}

/// Validated service settings.
#[derive(Clone)]
pub struct Settings {
    /// PostgreSQL settings.
    pub database: DatabaseSettings,
    /// HTTP settings.
    pub http: HttpSettings,
    /// Project-owned ciphertext root.
    pub document_store_root: PathBuf,
    /// Mock provider key files.
    pub keys: KeySettings,
    /// Audit export bounds.
    pub audit: AuditSettings,
    /// Mock identity credential file.
    pub identity_credentials_file: PathBuf,
    /// Diagnostic record switches.
    pub diagnostics: DiagnosticsSettings,
}

/// Which diagnostic records the server writes. Counters and startup-failure records are always on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiagnosticsSettings {
    /// Whether request and use-case span records are written, from
    /// `DOCCHAIN_DIAGNOSTICS__SPANS` (`on`, the default, or `off`).
    pub spans: bool,
}

/// Validated PostgreSQL coordinates.
#[derive(Clone, Debug)]
pub struct DatabaseSettings {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) name: String,
    pub(crate) user: String,
    pub(crate) password: Secret,
    pub(crate) max_connections: u32,
    pub(crate) schema: DatabaseSchema,
}

/// A PostgreSQL schema name safe to place in the connection `search_path`. It is never
/// `public`, which is shared by every role and not owned by the project.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseSchema(String);

impl DatabaseSchema {
    fn new(value: Option<&str>) -> Result<Self, SettingsError> {
        const KEY: &str = "DOCCHAIN_DATABASE__SCHEMA";
        let value = value.ok_or(SettingsError::new(KEY, "is required"))?;
        if !is_identifier(value) {
            return Err(SettingsError::new(
                KEY,
                "must be a lower-case PostgreSQL identifier",
            ));
        }
        if value == "public" {
            return Err(SettingsError::new(
                KEY,
                "must not be public; use a schema the migration owner owns",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `value` is a lower-case, unquoted PostgreSQL identifier of at most 63 bytes.
fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

/// Validated settings for `docchain-migrate`, which connects only as the migration owner.
///
/// It never reads the runtime role's password. Its `Debug` output hides the owner password.
#[derive(Clone, Debug)]
pub struct MigrationSettings {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) name: String,
    pub(crate) schema: DatabaseSchema,
    /// The runtime role that migrations grant to, from `DOCCHAIN_DATABASE__USER`.
    pub(crate) runtime_role: String,
    /// The migration owner, from `DOCCHAIN_MIGRATION__USER`.
    pub(crate) owner: String,
    pub(crate) owner_password: Secret,
}

impl MigrationSettings {
    /// Reads the `DOCCHAIN_` environment once and validates the migration settings.
    ///
    /// # Errors
    ///
    /// Returns a bounded error naming the missing or malformed key, never its value.
    pub fn from_env() -> Result<Self, SettingsError> {
        Self::from_unicode_map(docchain_variables(env::vars_os().collect())?)
    }

    /// Parses migration settings from a supplied map.
    ///
    /// # Errors
    ///
    /// Returns a bounded error naming the missing or malformed key, never its value.
    pub fn from_map(values: HashMap<String, String>) -> Result<Self, SettingsError> {
        Self::from_unicode_map(docchain_variables(os_map(values))?)
    }

    fn from_unicode_map(values: HashMap<String, String>) -> Result<Self, SettingsError> {
        let get = |key: &'static str| values.get(key).map(String::as_str);
        let (host, port, name, schema) = coordinates(&get)?;
        let owner = get("DOCCHAIN_MIGRATION__USER")
            .filter(|value| !value.is_empty())
            .ok_or(SettingsError::new(
                "DOCCHAIN_MIGRATION__USER",
                "is required",
            ))?
            .to_owned();
        let runtime_role = get("DOCCHAIN_DATABASE__USER")
            .ok_or(SettingsError::new("DOCCHAIN_DATABASE__USER", "is required"))?;
        if !is_identifier(runtime_role) {
            return Err(SettingsError::new(
                "DOCCHAIN_DATABASE__USER",
                "must be a lower-case PostgreSQL identifier",
            ));
        }
        if runtime_role == owner {
            return Err(SettingsError::new(
                "DOCCHAIN_DATABASE__USER",
                "must differ from DOCCHAIN_MIGRATION__USER",
            ));
        }
        let owner_password = secret(
            &get,
            "DOCCHAIN_MIGRATION__PASSWORD",
            "DOCCHAIN_MIGRATION__PASSWORD_FILE",
        )?;
        Ok(Self {
            host,
            port,
            name,
            schema,
            runtime_role: runtime_role.to_owned(),
            owner,
            owner_password,
        })
    }
}

/// Validated HTTP limits.
#[derive(Clone, Copy, Debug)]
pub struct HttpSettings {
    /// Listener address.
    pub bind: SocketAddr,
    /// End-to-end request deadline.
    pub request_timeout: Duration,
    /// Maximum concurrent requests.
    pub max_in_flight: usize,
    /// Graceful drain deadline.
    pub shutdown_timeout: Duration,
}

/// Paths to mock-provider key material.
#[derive(Clone)]
pub struct KeySettings {
    pub(crate) registry_authority_public: PathBuf,
    pub(crate) bindings: PathBuf,
    pub(crate) wallet_signing_private: Vec<PathBuf>,
    pub(crate) wallet_encryption_private: Vec<PathBuf>,
    pub(crate) audit_private: PathBuf,
    pub(crate) audit_public_key_fingerprint: [u8; 32],
}

/// Bounded independent-audit export settings.
#[derive(Clone, Copy, Debug)]
pub struct AuditSettings {
    /// Maximum event count for a complete export.
    pub max_export_events: u32,
    /// Default number of events per page.
    pub default_page_size: u32,
}

impl fmt::Debug for Settings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Settings")
            .field("database", &self.database)
            .field("http", &self.http)
            .field("document_store_root", &"redacted")
            .field("keys", &self.keys)
            .field("audit", &self.audit)
            .field("identity_credentials_file", &"redacted")
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

impl fmt::Debug for KeySettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeySettings(redacted)")
    }
}

/// A bounded configuration error which names the key, never its value.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("invalid configuration key {key}: {reason}")]
pub struct SettingsError {
    key: String,
    reason: &'static str,
}

impl SettingsError {
    fn new(key: impl Into<String>, reason: &'static str) -> Self {
        Self {
            key: key.into(),
            reason,
        }
    }

    /// The key that failed, as the human-readable message names it.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Why the key failed: a fixed text that never includes the value.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl Settings {
    /// Reads the `DOCCHAIN_` environment once and validates every setting.
    ///
    /// # Errors
    ///
    /// Returns a bounded error naming the missing or malformed key.
    pub fn from_env() -> Result<Self, SettingsError> {
        Self::from_os_map(env::vars_os().collect())
    }

    /// Parses settings from a supplied map, for deterministic composition tests.
    ///
    /// # Errors
    ///
    /// Returns a bounded error naming the missing or malformed key.
    pub fn from_map(values: HashMap<String, String>) -> Result<Self, SettingsError> {
        Self::from_os_map(os_map(values))
    }

    fn from_os_map(values: HashMap<OsString, OsString>) -> Result<Self, SettingsError> {
        Self::from_unicode_map(docchain_variables(values)?)
    }

    fn from_unicode_map(values: HashMap<String, String>) -> Result<Self, SettingsError> {
        // The server holds exactly one database credential, the runtime role's. A migration
        // owner key in its environment is refused, naming the first such key.
        if let Some(key) = values
            .keys()
            .filter(|key| key.starts_with("DOCCHAIN_MIGRATION__"))
            .min()
        {
            return Err(SettingsError::new(
                key.clone(),
                "must not be set for the server; only docchain-migrate reads it",
            ));
        }
        let get = |key: &'static str| values.get(key).map(String::as_str);
        let (host, port, name, schema) = coordinates(&get)?;
        let user = get("DOCCHAIN_DATABASE__USER")
            .unwrap_or("docchain")
            .to_owned();
        let password = secret(
            &get,
            "DOCCHAIN_DATABASE__PASSWORD",
            "DOCCHAIN_DATABASE__PASSWORD_FILE",
        )?;
        let max_connections = parse_or(
            get("DOCCHAIN_DATABASE__MAX_CONNECTIONS"),
            10_u32,
            "DOCCHAIN_DATABASE__MAX_CONNECTIONS",
        )?;
        if !(2..=64).contains(&max_connections) {
            return Err(SettingsError::new(
                "DOCCHAIN_DATABASE__MAX_CONNECTIONS",
                "must be from 2 through 64",
            ));
        }

        let bind = get("DOCCHAIN_HTTP__BIND")
            .unwrap_or("127.0.0.1:3000")
            .parse()
            .map_err(|_| SettingsError::new("DOCCHAIN_HTTP__BIND", "must be a socket address"))?;
        let request_timeout = millis(
            get("DOCCHAIN_HTTP__REQUEST_TIMEOUT_MS"),
            5_000,
            "DOCCHAIN_HTTP__REQUEST_TIMEOUT_MS",
        )?;
        let max_in_flight = parse_or(
            get("DOCCHAIN_HTTP__MAX_IN_FLIGHT"),
            64_usize,
            "DOCCHAIN_HTTP__MAX_IN_FLIGHT",
        )?;
        if !(1..=1_024).contains(&max_in_flight) {
            return Err(SettingsError::new(
                "DOCCHAIN_HTTP__MAX_IN_FLIGHT",
                "must be from 1 through 1024",
            ));
        }
        let shutdown_timeout = millis(
            get("DOCCHAIN_HTTP__SHUTDOWN_TIMEOUT_MS"),
            10_000,
            "DOCCHAIN_HTTP__SHUTDOWN_TIMEOUT_MS",
        )?;

        let document_store_root = required_path(
            get("DOCCHAIN_DOCUMENT_STORE__ROOT"),
            "DOCCHAIN_DOCUMENT_STORE__ROOT",
        )?;
        if !document_store_root.is_absolute() || document_store_root == Path::new("/") {
            return Err(SettingsError::new(
                "DOCCHAIN_DOCUMENT_STORE__ROOT",
                "must be an absolute non-root path",
            ));
        }

        let audit_public_key_fingerprint = decode_b64_32(
            get("DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT").ok_or(SettingsError::new(
                "DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT",
                "is required",
            ))?,
            "DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT",
        )?;
        let max_export_events = parse_or(
            get("DOCCHAIN_AUDIT__MAX_EXPORT_EVENTS"),
            100_000_u32,
            "DOCCHAIN_AUDIT__MAX_EXPORT_EVENTS",
        )?;
        if !(1..=100_000).contains(&max_export_events) {
            return Err(SettingsError::new(
                "DOCCHAIN_AUDIT__MAX_EXPORT_EVENTS",
                "must be from 1 through 100000",
            ));
        }
        let default_page_size = parse_or(
            get("DOCCHAIN_AUDIT__DEFAULT_PAGE_SIZE"),
            100_u32,
            "DOCCHAIN_AUDIT__DEFAULT_PAGE_SIZE",
        )?;
        if !(1..=500).contains(&default_page_size) {
            return Err(SettingsError::new(
                "DOCCHAIN_AUDIT__DEFAULT_PAGE_SIZE",
                "must be from 1 through 500",
            ));
        }
        let spans = match get("DOCCHAIN_DIAGNOSTICS__SPANS") {
            None | Some("on") => true,
            Some("off") => false,
            Some(_) => {
                return Err(SettingsError::new(
                    "DOCCHAIN_DIAGNOSTICS__SPANS",
                    "must be on or off",
                ));
            }
        };

        Ok(Self {
            database: DatabaseSettings {
                host,
                port,
                name,
                user,
                password,
                max_connections,
                schema,
            },
            http: HttpSettings {
                bind,
                request_timeout,
                max_in_flight,
                shutdown_timeout,
            },
            document_store_root,
            keys: KeySettings {
                registry_authority_public: required_path(
                    get("DOCCHAIN_KEYS__REGISTRY_AUTHORITY_PUBLIC_KEY_FILE"),
                    "DOCCHAIN_KEYS__REGISTRY_AUTHORITY_PUBLIC_KEY_FILE",
                )?,
                bindings: required_path(
                    get("DOCCHAIN_KEYS__BINDINGS_FILE"),
                    "DOCCHAIN_KEYS__BINDINGS_FILE",
                )?,
                wallet_signing_private: required_paths(
                    get("DOCCHAIN_KEYS__WALLET_SIGNING_PRIVATE_KEY_FILES"),
                    "DOCCHAIN_KEYS__WALLET_SIGNING_PRIVATE_KEY_FILES",
                )?,
                wallet_encryption_private: required_paths(
                    get("DOCCHAIN_KEYS__WALLET_ENCRYPTION_PRIVATE_KEY_FILES"),
                    "DOCCHAIN_KEYS__WALLET_ENCRYPTION_PRIVATE_KEY_FILES",
                )?,
                audit_private: required_path(
                    get("DOCCHAIN_KEYS__AUDIT_PRIVATE_KEY_FILE"),
                    "DOCCHAIN_KEYS__AUDIT_PRIVATE_KEY_FILE",
                )?,
                audit_public_key_fingerprint,
            },
            audit: AuditSettings {
                max_export_events,
                default_page_size,
            },
            identity_credentials_file: required_path(
                get("DOCCHAIN_IDENTITY__CREDENTIALS_FILE"),
                "DOCCHAIN_IDENTITY__CREDENTIALS_FILE",
            )?,
            diagnostics: DiagnosticsSettings { spans },
        })
    }
}

/// Refuses `PGOPTIONS`, keeps only `DOCCHAIN_` variables, and requires each to be Unicode.
fn docchain_variables(
    values: HashMap<OsString, OsString>,
) -> Result<HashMap<String, String>, SettingsError> {
    if values.contains_key(OsStr::new("PGOPTIONS")) {
        return Err(SettingsError::new(
            "PGOPTIONS",
            "must not be set; use DOCCHAIN_DATABASE__SCHEMA",
        ));
    }
    let mut unicode = HashMap::new();
    for (key, value) in values {
        let key_lossy = key.to_string_lossy();
        if !key_lossy.starts_with("DOCCHAIN_") {
            continue;
        }
        let key = key
            .into_string()
            .map_err(|_| SettingsError::new("DOCCHAIN_*", "name is not Unicode"))?;
        let value = value
            .into_string()
            .map_err(|_| SettingsError::new(key.clone(), "value is not Unicode"))?;
        unicode.insert(key, value);
    }
    Ok(unicode)
}

fn os_map(values: HashMap<String, String>) -> HashMap<OsString, OsString> {
    values
        .into_iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect()
}

/// The host, port, database, and schema both binaries read.
fn coordinates<'a>(
    get: &impl Fn(&'static str) -> Option<&'a str>,
) -> Result<(String, u16, String, DatabaseSchema), SettingsError> {
    let host = get("DOCCHAIN_DATABASE__HOST")
        .unwrap_or("postgres")
        .to_owned();
    let port = parse_or(
        get("DOCCHAIN_DATABASE__PORT"),
        5432,
        "DOCCHAIN_DATABASE__PORT",
    )?;
    let name = get("DOCCHAIN_DATABASE__NAME")
        .unwrap_or("docchain")
        .to_owned();
    let schema = DatabaseSchema::new(get("DOCCHAIN_DATABASE__SCHEMA"))?;
    Ok((host, port, name, schema))
}

/// A password given directly under `key`, or read from the file `file_key` names.
fn secret<'a>(
    get: &impl Fn(&'static str) -> Option<&'a str>,
    key: &'static str,
    file_key: &'static str,
) -> Result<Secret, SettingsError> {
    match get(key) {
        Some(value) if !value.is_empty() => Ok(Secret(value.to_owned())),
        Some(_) => Err(SettingsError::new(key, "must not be empty")),
        None => {
            let path = required_path(get(file_key), file_key)?;
            let value = std::fs::read_to_string(path)
                .map_err(|_| SettingsError::new(file_key, "cannot read secret file"))?;
            let value = value.trim_end();
            if value.is_empty() {
                return Err(SettingsError::new(file_key, "secret file is empty"));
            }
            Ok(Secret(value.to_owned()))
        }
    }
}

fn decode_b64_32(value: &str, key: &'static str) -> Result<[u8; 32], SettingsError> {
    if value.contains('=') || value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(SettingsError::new(
            key,
            "must be canonical unpadded base64url",
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SettingsError::new(key, "must be canonical unpadded base64url"))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(SettingsError::new(
            key,
            "must be canonical unpadded base64url",
        ));
    }
    decoded
        .try_into()
        .map_err(|_| SettingsError::new(key, "must encode exactly 32 bytes"))
}

fn parse_or<T: std::str::FromStr>(
    value: Option<&str>,
    default: T,
    key: &'static str,
) -> Result<T, SettingsError> {
    value.map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|_| SettingsError::new(key, "has an invalid value"))
    })
}

fn millis(value: Option<&str>, default: u64, key: &'static str) -> Result<Duration, SettingsError> {
    let millis = parse_or(value, default, key)?;
    if !(1..=60_000).contains(&millis) {
        return Err(SettingsError::new(key, "must be from 1 through 60000"));
    }
    Ok(Duration::from_millis(millis))
}

fn required_path(value: Option<&str>, key: &'static str) -> Result<PathBuf, SettingsError> {
    value
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(SettingsError::new(key, "is required"))
}

fn required_paths(value: Option<&str>, key: &'static str) -> Result<Vec<PathBuf>, SettingsError> {
    let paths = value
        .unwrap_or_default()
        .split(',')
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if paths.is_empty() {
        return Err(SettingsError::new(key, "requires at least one path"));
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_values_name_the_key_without_the_value() {
        let mut values = HashMap::new();
        values.insert(
            "DOCCHAIN_DATABASE__PORT".to_owned(),
            "not-a-port".to_owned(),
        );
        let error = Settings::from_map(values).expect_err("bad port");
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("DOCCHAIN_DATABASE__PORT"));
        assert!(!diagnostic.contains("not-a-port"));
    }

    #[test]
    fn complete_settings_apply_documented_defaults() {
        let settings = complete_settings().expect("settings");
        assert_eq!(settings.database.port, 5432);
        assert_eq!(settings.database.max_connections, 10);
        assert_eq!(settings.database.schema.as_str(), "docchain");
        assert_eq!(settings.database.user, "docchain");
        assert_eq!(
            settings.http.bind,
            "127.0.0.1:3000".parse().expect("address")
        );
        assert_eq!(settings.http.request_timeout, Duration::from_secs(5));
        assert_eq!(settings.http.max_in_flight, 64);
        assert_eq!(settings.http.shutdown_timeout, Duration::from_secs(10));
        assert_eq!(settings.keys.wallet_encryption_private.len(), 1);
        assert_eq!(settings.audit.max_export_events, 100_000);
        assert_eq!(settings.audit.default_page_size, 100);
        assert!(settings.diagnostics.spans);
    }

    #[test]
    fn spans_switch_is_on_or_off_and_nothing_else() {
        for (value, spans) in [("on", true), ("off", false)] {
            let mut values = complete_values();
            values.insert("DOCCHAIN_DIAGNOSTICS__SPANS".to_owned(), value.to_owned());
            assert_eq!(
                Settings::from_map(values).expect(value).diagnostics.spans,
                spans
            );
        }
        for value in ["", "ON", "true", "1", "invented-spans-value"] {
            let mut values = complete_values();
            values.insert("DOCCHAIN_DIAGNOSTICS__SPANS".to_owned(), value.to_owned());
            let error = Settings::from_map(values).expect_err(value);
            assert_eq!(
                (error.key(), error.reason()),
                ("DOCCHAIN_DIAGNOSTICS__SPANS", "must be on or off")
            );
            assert!(!error.to_string().contains("invented-spans-value"));
        }
    }

    #[test]
    fn accessors_return_the_stored_key_and_reason() {
        let mut values = complete_values();
        values.insert("DOCCHAIN_HTTP__MAX_IN_FLIGHT".to_owned(), "0".to_owned());
        let error = Settings::from_map(values).expect_err("bad limit");
        assert_eq!(error.key(), "DOCCHAIN_HTTP__MAX_IN_FLIGHT");
        assert_eq!(error.reason(), "must be from 1 through 1024");
        assert_eq!(
            error.to_string(),
            "invalid configuration key DOCCHAIN_HTTP__MAX_IN_FLIGHT: must be from 1 through 1024"
        );
    }

    #[test]
    fn each_missing_or_unsafe_value_names_its_key() {
        let cases: [(&str, Option<&str>); 18] = [
            ("DOCCHAIN_DOCUMENT_STORE__ROOT", None),
            ("DOCCHAIN_DOCUMENT_STORE__ROOT", Some("relative/documents")),
            ("DOCCHAIN_DOCUMENT_STORE__ROOT", Some("/")),
            ("DOCCHAIN_KEYS__REGISTRY_AUTHORITY_PUBLIC_KEY_FILE", None),
            ("DOCCHAIN_KEYS__BINDINGS_FILE", Some("")),
            ("DOCCHAIN_KEYS__WALLET_SIGNING_PRIVATE_KEY_FILES", Some(",")),
            ("DOCCHAIN_KEYS__WALLET_ENCRYPTION_PRIVATE_KEY_FILES", None),
            ("DOCCHAIN_KEYS__AUDIT_PRIVATE_KEY_FILE", None),
            ("DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT", None),
            ("DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT", Some("AA==")),
            ("DOCCHAIN_AUDIT__MAX_EXPORT_EVENTS", Some("100001")),
            ("DOCCHAIN_AUDIT__DEFAULT_PAGE_SIZE", Some("501")),
            ("DOCCHAIN_IDENTITY__CREDENTIALS_FILE", None),
            ("DOCCHAIN_DATABASE__PASSWORD", Some("")),
            ("DOCCHAIN_DATABASE__MAX_CONNECTIONS", Some("65")),
            ("DOCCHAIN_HTTP__BIND", Some("localhost")),
            ("DOCCHAIN_HTTP__MAX_IN_FLIGHT", Some("0")),
            ("DOCCHAIN_HTTP__SHUTDOWN_TIMEOUT_MS", Some("60001")),
        ];
        for (key, value) in cases {
            let mut values = complete_values();
            match value {
                Some(value) => values.insert(key.to_owned(), value.to_owned()),
                None => values.remove(key),
            };
            let error = Settings::from_map(values).expect_err(key);
            assert_eq!(error.key, key);
            if let Some(value) = value.filter(|value| value.len() > 1) {
                assert!(!error.to_string().contains(value), "{key}");
            }
        }
        let mut values = complete_values();
        values.remove("DOCCHAIN_DATABASE__PASSWORD");
        values.insert(
            "DOCCHAIN_DATABASE__PASSWORD_FILE".to_owned(),
            "/nonexistent/docchain/password".to_owned(),
        );
        let error = Settings::from_map(values).expect_err("unreadable password file");
        assert_eq!(error.key, "DOCCHAIN_DATABASE__PASSWORD_FILE");
        assert!(!error.to_string().contains("/nonexistent/"));
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let secret = Secret("invented-secret".to_owned());
        assert_eq!(format!("{secret:?}"), "Secret(redacted)");
    }

    #[test]
    fn settings_debug_output_redacts_paths() {
        let settings = complete_settings().expect("settings");
        let debug = format!("{settings:?}");
        assert!(!debug.contains("/private/"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn pgoptions_fails_startup_naming_the_variable() {
        let mut values = complete_values()
            .into_iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect::<HashMap<_, _>>();
        values.insert(
            OsString::from("PGOPTIONS"),
            OsString::from("-c search_path=public"),
        );
        let error = Settings::from_os_map(values).expect_err("PGOPTIONS must be refused");
        assert_eq!(error.key, "PGOPTIONS");
        assert!(!error.to_string().contains("search_path"));
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_foreign_variables_are_ignored() {
        use std::os::unix::ffi::OsStringExt as _;

        let mut values = complete_values()
            .into_iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect::<HashMap<_, _>>();
        values.insert(
            OsString::from_vec(vec![0xff]),
            OsString::from_vec(vec![0xff]),
        );
        Settings::from_os_map(values).expect("foreign variable is ignored");
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_docchain_variable_fails_without_its_value() {
        use std::os::unix::ffi::OsStringExt as _;

        let mut values = complete_values()
            .into_iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value)))
            .collect::<HashMap<_, _>>();
        let mut name = b"DOCCHAIN_BAD_".to_vec();
        name.push(0xff);
        values.insert(OsString::from_vec(name), OsString::from_vec(vec![0xfe]));
        let error = Settings::from_os_map(values).expect_err("invalid Docchain variable");
        assert_eq!(error.key, "DOCCHAIN_*");
        assert!(!error.to_string().contains('\u{fffd}'));
    }

    #[test]
    fn both_loaders_require_a_schema_other_than_public() {
        for value in [None, Some("public"), Some("Public"), Some("")] {
            let mut server = complete_values();
            let mut migrator = migration_values();
            match value {
                Some(value) => {
                    server.insert("DOCCHAIN_DATABASE__SCHEMA".to_owned(), value.to_owned());
                    migrator.insert("DOCCHAIN_DATABASE__SCHEMA".to_owned(), value.to_owned());
                }
                None => {
                    server.remove("DOCCHAIN_DATABASE__SCHEMA");
                    migrator.remove("DOCCHAIN_DATABASE__SCHEMA");
                }
            }
            let server = Settings::from_map(server).expect_err("server schema");
            let migrator = MigrationSettings::from_map(migrator).expect_err("migrator schema");
            for error in [server, migrator] {
                assert_eq!(error.key, "DOCCHAIN_DATABASE__SCHEMA", "{value:?}");
            }
        }
    }

    #[test]
    fn server_refuses_any_migration_owner_key_naming_it() {
        for key in [
            "DOCCHAIN_MIGRATION__USER",
            "DOCCHAIN_MIGRATION__PASSWORD",
            "DOCCHAIN_MIGRATION__PASSWORD_FILE",
            "DOCCHAIN_MIGRATION__OTHER",
        ] {
            let mut values = complete_values();
            values.insert(key.to_owned(), "invented-owner-value".to_owned());
            let error = Settings::from_map(values).expect_err(key);
            assert_eq!(error.key, key);
            assert!(!error.to_string().contains("invented-owner-value"));
        }
        let mut values = complete_values();
        values.insert("DOCCHAIN_MIGRATION__USER".to_owned(), "owner".to_owned());
        values.insert(
            "DOCCHAIN_MIGRATION__PASSWORD_FILE".to_owned(),
            "/private/owner".to_owned(),
        );
        assert_eq!(
            Settings::from_map(values).expect_err("two keys").key,
            "DOCCHAIN_MIGRATION__PASSWORD_FILE"
        );
    }

    #[test]
    fn migration_settings_read_only_the_owner_credential() {
        let settings = MigrationSettings::from_map(migration_values()).expect("settings");
        assert_eq!(
            (
                settings.owner.as_str(),
                settings.runtime_role.as_str(),
                settings.schema.as_str(),
                settings.owner_password.expose(),
            ),
            (
                "docchain_owner",
                "docchain_runtime",
                "docchain",
                "owner-secret"
            )
        );
        // The runtime password is never read, even when its file cannot be.
        let mut values = migration_values();
        values.insert(
            "DOCCHAIN_DATABASE__PASSWORD_FILE".to_owned(),
            "/nonexistent/runtime".to_owned(),
        );
        assert!(MigrationSettings::from_map(values).is_ok());
        let debug = format!("{settings:?}");
        assert!(!debug.contains("owner-secret"));
        assert!(debug.contains("Secret(redacted)"));
    }

    #[test]
    fn migration_settings_name_each_bad_key() {
        let cases: [(&str, Option<&str>, &str); 7] = [
            ("DOCCHAIN_MIGRATION__USER", None, "DOCCHAIN_MIGRATION__USER"),
            (
                "DOCCHAIN_MIGRATION__USER",
                Some(""),
                "DOCCHAIN_MIGRATION__USER",
            ),
            (
                "DOCCHAIN_MIGRATION__USER",
                Some("docchain_runtime"),
                "DOCCHAIN_DATABASE__USER",
            ),
            ("DOCCHAIN_DATABASE__USER", None, "DOCCHAIN_DATABASE__USER"),
            (
                "DOCCHAIN_DATABASE__USER",
                Some("Runtime"),
                "DOCCHAIN_DATABASE__USER",
            ),
            (
                "DOCCHAIN_DATABASE__USER",
                Some("runtime; drop"),
                "DOCCHAIN_DATABASE__USER",
            ),
            (
                "DOCCHAIN_MIGRATION__PASSWORD",
                None,
                "DOCCHAIN_MIGRATION__PASSWORD_FILE",
            ),
        ];
        for (key, value, named) in cases {
            let mut values = migration_values();
            match value {
                Some(value) => values.insert(key.to_owned(), value.to_owned()),
                None => values.remove(key),
            };
            let error = MigrationSettings::from_map(values).expect_err(key);
            assert_eq!(error.key, named, "{key} = {value:?}");
            assert!(!error.to_string().contains("owner-secret"));
        }
    }

    fn migration_values() -> HashMap<String, String> {
        let mut values = HashMap::new();
        for (key, value) in [
            ("DOCCHAIN_DATABASE__SCHEMA", "docchain"),
            ("DOCCHAIN_DATABASE__USER", "docchain_runtime"),
            ("DOCCHAIN_MIGRATION__USER", "docchain_owner"),
            ("DOCCHAIN_MIGRATION__PASSWORD", "owner-secret"),
        ] {
            values.insert(key.to_owned(), value.to_owned());
        }
        values
    }

    fn complete_settings() -> Result<Settings, SettingsError> {
        Settings::from_map(complete_values())
    }

    fn complete_values() -> HashMap<String, String> {
        let mut values = HashMap::new();
        values.insert(
            "DOCCHAIN_DATABASE__PASSWORD".to_owned(),
            "secret".to_owned(),
        );
        values.insert(
            "DOCCHAIN_DATABASE__SCHEMA".to_owned(),
            "docchain".to_owned(),
        );
        values.insert(
            "DOCCHAIN_DOCUMENT_STORE__ROOT".to_owned(),
            "/private/documents".to_owned(),
        );
        for key in [
            "DOCCHAIN_KEYS__REGISTRY_AUTHORITY_PUBLIC_KEY_FILE",
            "DOCCHAIN_KEYS__BINDINGS_FILE",
            "DOCCHAIN_KEYS__WALLET_SIGNING_PRIVATE_KEY_FILES",
            "DOCCHAIN_KEYS__WALLET_ENCRYPTION_PRIVATE_KEY_FILES",
            "DOCCHAIN_KEYS__AUDIT_PRIVATE_KEY_FILE",
            "DOCCHAIN_IDENTITY__CREDENTIALS_FILE",
        ] {
            values.insert(key.to_owned(), format!("/private/{key}"));
        }
        values.insert(
            "DOCCHAIN_KEYS__AUDIT_PUBLIC_KEY_FINGERPRINT".to_owned(),
            URL_SAFE_NO_PAD.encode([1; 32]),
        );
        values
    }
}
