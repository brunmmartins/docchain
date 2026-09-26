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
    /// Mock identity credential file.
    pub identity_credentials_file: PathBuf,
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

/// A PostgreSQL schema name safe to place in the connection `search_path`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DatabaseSchema(String);

impl DatabaseSchema {
    fn new(value: &str) -> Result<Self, SettingsError> {
        let valid = !value.is_empty()
            && value.len() <= 63
            && value
                .bytes()
                .next()
                .is_some_and(|byte| byte == b'_' || byte.is_ascii_lowercase())
            && value
                .bytes()
                .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit());
        if !valid {
            return Err(SettingsError::new(
                "DOCCHAIN_DATABASE__SCHEMA",
                "must be a lower-case PostgreSQL identifier",
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
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
}

impl fmt::Debug for Settings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Settings")
            .field("database", &self.database)
            .field("http", &self.http)
            .field("document_store_root", &"redacted")
            .field("keys", &self.keys)
            .field("identity_credentials_file", &"redacted")
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
        Self::from_os_map(
            values
                .into_iter()
                .map(|(key, value)| (OsString::from(key), OsString::from(value)))
                .collect(),
        )
    }

    fn from_os_map(values: HashMap<OsString, OsString>) -> Result<Self, SettingsError> {
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
        Self::from_unicode_map(unicode)
    }

    fn from_unicode_map(values: HashMap<String, String>) -> Result<Self, SettingsError> {
        let get = |key: &'static str| values.get(key).map(String::as_str);
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
        let user = get("DOCCHAIN_DATABASE__USER")
            .unwrap_or("docchain")
            .to_owned();
        let password = match get("DOCCHAIN_DATABASE__PASSWORD") {
            Some(value) if !value.is_empty() => Secret(value.to_owned()),
            Some(_) => {
                return Err(SettingsError::new(
                    "DOCCHAIN_DATABASE__PASSWORD",
                    "must not be empty",
                ));
            }
            None => {
                let key = "DOCCHAIN_DATABASE__PASSWORD_FILE";
                let path = required_path(get(key), key)?;
                let value = std::fs::read_to_string(path)
                    .map_err(|_| SettingsError::new(key, "cannot read secret file"))?;
                let value = value.trim_end();
                if value.is_empty() {
                    return Err(SettingsError::new(key, "secret file is empty"));
                }
                Secret(value.to_owned())
            }
        };
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
        let schema = DatabaseSchema::new(get("DOCCHAIN_DATABASE__SCHEMA").unwrap_or("public"))?;

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
            },
            identity_credentials_file: required_path(
                get("DOCCHAIN_IDENTITY__CREDENTIALS_FILE"),
                "DOCCHAIN_IDENTITY__CREDENTIALS_FILE",
            )?,
        })
    }
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
        assert_eq!(settings.database.schema.as_str(), "public");
        assert_eq!(
            settings.http.bind,
            "127.0.0.1:3000".parse().expect("address")
        );
        assert_eq!(settings.http.request_timeout, Duration::from_secs(5));
        assert_eq!(settings.http.max_in_flight, 64);
        assert_eq!(settings.http.shutdown_timeout, Duration::from_secs(10));
        assert_eq!(settings.keys.wallet_encryption_private.len(), 1);
    }

    #[test]
    fn each_missing_or_unsafe_value_names_its_key() {
        let cases: [(&str, Option<&str>); 14] = [
            ("DOCCHAIN_DOCUMENT_STORE__ROOT", None),
            ("DOCCHAIN_DOCUMENT_STORE__ROOT", Some("relative/documents")),
            ("DOCCHAIN_DOCUMENT_STORE__ROOT", Some("/")),
            ("DOCCHAIN_KEYS__REGISTRY_AUTHORITY_PUBLIC_KEY_FILE", None),
            ("DOCCHAIN_KEYS__BINDINGS_FILE", Some("")),
            ("DOCCHAIN_KEYS__WALLET_SIGNING_PRIVATE_KEY_FILES", Some(",")),
            ("DOCCHAIN_KEYS__WALLET_ENCRYPTION_PRIVATE_KEY_FILES", None),
            ("DOCCHAIN_KEYS__AUDIT_PRIVATE_KEY_FILE", None),
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
        values
    }
}
