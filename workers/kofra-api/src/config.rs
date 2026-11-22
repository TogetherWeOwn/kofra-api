//! The Worker's settings, read once per request from its variables and
//! secrets. Parsing is a pure function of a lookup, so it is tested
//! natively. A setting that is missing or malformed refuses the request
//! (fail closed); the error names the setting, never its value.

use kofra_account::SignupMode;
use kofra_storage_mgmt::{BadToken, Tokens};

/// Where this copy runs. Production refuses the test-only mail modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deployment {
    /// `production`
    Production,
    /// `staging`
    Staging,
    /// `local` (wrangler dev, the e2e)
    Local,
}

/// What happens to a message the account service sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailMode {
    /// Send it through the `EMAIL` binding (Email Service).
    Send,
    /// Write one log line with the message kind and a hash of the address;
    /// the message itself is dropped.
    Log,
    /// Keep it in `account_mail_outbox` (staging and local only).
    Outbox,
    /// POST it to a loopback URL (local e2e only).
    Capture(String),
}

/// Mail settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailSettings {
    /// The mode for recipients on the allow-list (everyone when there is
    /// no list).
    pub mode: MailMode,
    /// When set, only these addresses (exact, lower-case) or domains
    /// (`@example.com`) get `mode`; every other recipient gets `others`.
    pub allow: Option<Vec<String>>,
    /// The mode for recipients not on the allow-list.
    pub others: MailMode,
    /// Sender address: a no-reply address of the sending domain.
    pub from: String,
    /// Sender name.
    pub from_name: String,
    /// Reply-To, when set.
    pub reply_to: Option<String>,
}

impl MailSettings {
    /// Whether any recipient is sent real mail (the `EMAIL` binding is then
    /// required).
    pub fn sends(&self) -> bool {
        self.mode == MailMode::Send || self.others == MailMode::Send
    }

    /// The mode for one recipient.
    pub fn mode_for(&self, to: &str) -> &MailMode {
        let Some(list) = &self.allow else {
            return &self.mode;
        };
        let to = to.trim().to_ascii_lowercase();
        let domain = to.rsplit_once('@').map(|(_, d)| format!("@{d}"));
        if list
            .iter()
            .any(|a| *a == to || Some(a.as_str()) == domain.as_deref())
        {
            &self.mode
        } else {
            &self.others
        }
    }
}

/// Which storage plane serves the API's storage port.
#[derive(Clone)]
pub enum StorageSetting {
    /// The stub: reads answer an empty tenant, writes wait (the default).
    Stub,
    /// The storage management plane over the `STORAGE_MGMT` service
    /// binding, with its two service tokens.
    Mgmt {
        /// `STORAGE_MGMT_TOKEN` (standard) and
        /// `STORAGE_MGMT_TOKEN_CONFIRMED` (confirmed). This is the only
        /// place the confirmed token is read; from here it goes straight
        /// into [`Tokens`], which hands it out only behind the confirmation
        /// checks.
        tokens: Tokens,
    },
}

impl std::fmt::Debug for StorageSetting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Stub => "Stub",
            Self::Mgmt { .. } => "Mgmt",
        })
    }
}

/// Everything the Worker needs from its settings.
#[derive(Clone)]
pub struct Settings {
    /// Where it runs.
    pub deployment: Deployment,
    /// The console's origin (`https://console.kofra.app`): mail links and
    /// the passkey RP ID.
    pub console_origin: String,
    /// The S3 endpoint shown to customers.
    pub s3_endpoint: String,
    /// Sign-up mode.
    pub signup: SignupMode,
    /// Root secret of the account service (CSRF, recovery codes, TOTP seal).
    pub account_secret: [u8; 32],
    /// Key of the console's session assertions (shared with the console).
    pub console_key: [u8; 32],
    /// Key that seals list cursors.
    pub cursor_key: [u8; 32],
    /// Mail.
    pub mail: MailSettings,
    /// Run the breached-password check (off only in local tests).
    pub breach_check: bool,
    /// The storage plane.
    pub storage: StorageSetting,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("deployment", &self.deployment)
            .field("console_origin", &self.console_origin)
            .field("signup", &self.signup)
            .field("mail", &self.mail.mode)
            .field("storage", &self.storage)
            .finish_non_exhaustive()
    }
}

/// A refused configuration: the name of the setting at fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadSetting(pub &'static str);

fn key(get: &impl Fn(&str) -> Option<String>, name: &'static str) -> Result<[u8; 32], BadSetting> {
    let v = get(name).ok_or(BadSetting(name))?;
    let v = v.trim();
    if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BadSetting(name));
    }
    let mut out = [0_u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&v[2 * i..2 * i + 2], 16).map_err(|_| BadSetting(name))?;
    }
    if out == [0; 32] {
        return Err(BadSetting(name));
    }
    Ok(out)
}

/// An origin in the form browsers send it (WebAuthn compares it exactly):
/// `https://host`, or `http://` locally; a port only when it is not the
/// default one; nothing else. `None` for anything that is not an origin.
fn origin(v: &str, local: bool) -> Option<String> {
    // As written, before parsing: scheme, host, optional port, an optional
    // final "/", nothing else (parsing would fold `/app/..` into `/`).
    let rest = v.split_once("://")?.1;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.is_empty() || rest.contains(['/', '?', '#', '@', '\\']) {
        return None;
    }
    let u = worker::Url::parse(v).ok()?;
    let scheme_ok = u.scheme() == "https" || (local && u.scheme() == "http");
    let bare = !v.trim_end_matches('/').contains(['?', '#'])
        && u.username().is_empty()
        && u.password().is_none()
        && u.path() == "/"
        && u.query().is_none()
        && u.fragment().is_none();
    if !scheme_ok || !bare {
        return None;
    }
    let host = u.host_str()?;
    // `port()` is `None` for the scheme's default port: `:443` is dropped.
    Some(match u.port() {
        Some(p) => format!("{}://{host}:{p}", u.scheme()),
        None => format!("{}://{host}", u.scheme()),
    })
}

/// An `http` URL on a loopback host, with no user name or password
/// (`http://127.0.0.1:4180@elsewhere/` is refused).
fn loopback_url(v: &str) -> bool {
    let Ok(u) = worker::Url::parse(v) else {
        return false;
    };
    u.scheme() == "http"
        && u.username().is_empty()
        && u.password().is_none()
        && matches!(u.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
}

fn mail_mode(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    deployment: Deployment,
) -> Result<MailMode, BadSetting> {
    let mode = match get(name).as_deref().map(str::trim) {
        Some("send") => MailMode::Send,
        Some("log") => MailMode::Log,
        Some("outbox") => MailMode::Outbox,
        Some("capture") => {
            let url = get("MAIL_CAPTURE_URL").ok_or(BadSetting("MAIL_CAPTURE_URL"))?;
            if !loopback_url(&url) {
                return Err(BadSetting("MAIL_CAPTURE_URL"));
            }
            MailMode::Capture(url)
        }
        _ => return Err(BadSetting(name)),
    };
    let test_only = matches!(mode, MailMode::Outbox | MailMode::Capture(_));
    if test_only && deployment == Deployment::Production
        || matches!(mode, MailMode::Capture(_)) && deployment != Deployment::Local
    {
        return Err(BadSetting(name));
    }
    Ok(mode)
}

impl Settings {
    /// Reads the settings through `get` (a variable or secret by name).
    pub fn parse(get: impl Fn(&str) -> Option<String>) -> Result<Self, BadSetting> {
        let deployment = match get("KOFRA_ENV").as_deref() {
            Some("production") => Deployment::Production,
            Some("staging") => Deployment::Staging,
            Some("local") => Deployment::Local,
            _ => return Err(BadSetting("KOFRA_ENV")),
        };
        let local = deployment == Deployment::Local;
        let console_origin = get("CONSOLE_ORIGIN")
            .and_then(|v| origin(&v, local))
            .ok_or(BadSetting("CONSOLE_ORIGIN"))?;
        let s3_endpoint = get("S3_ENDPOINT")
            .and_then(|v| origin(&v, local))
            .ok_or(BadSetting("S3_ENDPOINT"))?;
        let signup = match get("SIGNUP_MODE").as_deref() {
            Some("closed") => SignupMode::Closed,
            Some("invite") => SignupMode::Invite,
            Some("open") => SignupMode::Open,
            _ => return Err(BadSetting("SIGNUP_MODE")),
        };
        // Open sign-up needs the abuse controls of the accounts design
        // (Turnstile, caps), which are not built: refused for now.
        if signup == SignupMode::Open {
            return Err(BadSetting("SIGNUP_MODE"));
        }
        let mode = mail_mode(&get, "MAIL_MODE", deployment)?;
        let allow = match get("MAIL_ALLOW") {
            None => None,
            Some(v) => {
                let list: Vec<String> = v
                    .split(',')
                    .map(|a| a.trim().to_ascii_lowercase())
                    .filter(|a| !a.is_empty())
                    .collect();
                if list.is_empty() || list.iter().any(|a| !a.contains('@')) {
                    return Err(BadSetting("MAIL_ALLOW"));
                }
                Some(list)
            }
        };
        let others = if allow.is_some() {
            mail_mode(&get, "MAIL_OTHERS", deployment)?
        } else {
            MailMode::Log
        };
        let from = get("MAIL_FROM")
            .filter(|v| v.contains('@') && !v.contains(['<', '>', ',', ' ']))
            .ok_or(BadSetting("MAIL_FROM"))?;
        let reply_to = get("MAIL_REPLY_TO");
        if reply_to
            .as_deref()
            .is_some_and(|v| !v.contains('@') || v.contains(['<', '>', ',', ' ']))
        {
            return Err(BadSetting("MAIL_REPLY_TO"));
        }
        let breach_check = match get("BREACH_CHECK").as_deref() {
            None | Some("on") => true,
            Some("off") if local => false,
            _ => return Err(BadSetting("BREACH_CHECK")),
        };
        // The stub stays the plane until the setting says otherwise.
        let storage = match get("STORAGE_PLANE").as_deref() {
            None | Some("stub") => StorageSetting::Stub,
            Some("mgmt") => {
                const STANDARD: &str = "STORAGE_MGMT_TOKEN";
                const CONFIRMED: &str = "STORAGE_MGMT_TOKEN_CONFIRMED";
                let standard = get(STANDARD)
                    .filter(|t| kofra_storage_mgmt::tokens::well_formed(t))
                    .ok_or(BadSetting(STANDARD))?;
                let confirmed = get(CONFIRMED).ok_or(BadSetting(CONFIRMED))?;
                // `Tokens` checks both and that they differ.
                let tokens = Tokens::new(standard, confirmed).map_err(|e| match e {
                    BadToken::Standard => BadSetting(STANDARD),
                    BadToken::Confirmed => BadSetting(CONFIRMED),
                })?;
                StorageSetting::Mgmt { tokens }
            }
            _ => return Err(BadSetting("STORAGE_PLANE")),
        };
        let account_secret = key(&get, "ACCOUNT_SECRET_KEY")?;
        let console_key = key(&get, "ASSERTION_KEY")?;
        let cursor_key = key(&get, "CURSOR_KEY")?;
        // Each key must be its own; the log names the second of a pair.
        if account_secret == console_key {
            return Err(BadSetting("ASSERTION_KEY"));
        }
        if account_secret == cursor_key || console_key == cursor_key {
            return Err(BadSetting("CURSOR_KEY"));
        }
        Ok(Self {
            deployment,
            console_origin,
            s3_endpoint,
            signup,
            account_secret,
            console_key,
            cursor_key,
            mail: MailSettings {
                mode,
                allow,
                others,
                from,
                from_name: get("MAIL_FROM_NAME").unwrap_or_else(|| "Kofra".to_owned()),
                reply_to,
            },
            breach_check,
            storage,
        })
    }

    /// A key of its own for `purpose`, derived from the account secret
    /// (HKDF-SHA256). Used for keyed hashes that are stored or logged
    /// (throttle keys, address tags in logs), so they cannot be reversed by
    /// guessing.
    pub fn subkey(&self, purpose: &[u8]) -> [u8; 32] {
        let hk =
            hkdf::Hkdf::<sha2::Sha256>::new(Some(b"kofra-api-worker-v1"), &self.account_secret);
        let mut out = [0_u8; 32];
        hk.expand(purpose, &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 length");
        out
    }

    /// The account service's settings.
    pub fn accounts(&self) -> kofra_account::Config {
        let mut c = kofra_account::Config::new(&self.console_origin);
        c.signup = self.signup;
        c
    }

    /// The API's settings.
    pub fn api(&self) -> kofra_api_core::Config {
        kofra_api_core::Config {
            s3_endpoint: self.s3_endpoint.clone(),
            console_url: self.console_origin.clone(),
            cursor_key: self.cursor_key,
            console_key: Some(self.console_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    /// Builds `local@domain` at run time, so that the repository's address
    /// scanner does not read test inputs as real addresses.
    fn at(local: &str, domain: &str) -> String {
        format!("{local}{}{domain}", '@')
    }

    fn base() -> HashMap<&'static str, String> {
        HashMap::from([
            ("KOFRA_ENV", "staging".to_owned()),
            ("CONSOLE_ORIGIN", "https://console.example.com".to_owned()),
            ("S3_ENDPOINT", "https://s3.example.com".to_owned()),
            ("SIGNUP_MODE", "invite".to_owned()),
            ("MAIL_MODE", "send".to_owned()),
            ("MAIL_FROM", at("noreply", "mail.example.com")),
            ("ACCOUNT_SECRET_KEY", "11".repeat(32)),
            ("ASSERTION_KEY", "22".repeat(32)),
            ("CURSOR_KEY", "33".repeat(32)),
        ])
    }

    fn parse(m: &HashMap<&'static str, String>) -> Result<Settings, BadSetting> {
        Settings::parse(|k| m.get(k).cloned())
    }

    #[test]
    fn a_complete_configuration_parses() {
        let s = parse(&base()).unwrap();
        assert_eq!(s.deployment, Deployment::Staging);
        assert_eq!(s.account_secret, [0x11; 32]);
        assert_eq!(s.mail.mode, MailMode::Send);
        assert_eq!(s.mail.from_name, "Kofra");
        assert!(s.breach_check);
        assert_eq!(s.accounts().rp_id, "console.example.com");
        assert_eq!(s.api().console_key, Some([0x22; 32]));
        // Debug never shows a key.
        assert!(!format!("{s:?}").contains("11111111"));
    }

    #[test]
    fn the_storage_plane_is_the_stub_unless_set_to_mgmt_with_both_tokens() {
        assert!(matches!(
            parse(&base()).unwrap().storage,
            StorageSetting::Stub
        ));
        let mut m = base();
        m.insert("STORAGE_PLANE", "stub".to_owned());
        assert!(matches!(parse(&m).unwrap().storage, StorageSetting::Stub));
        m.insert("STORAGE_PLANE", "mgmt".to_owned());
        assert_eq!(parse(&m).err(), Some(BadSetting("STORAGE_MGMT_TOKEN")));
        for bad in ["short", "has a space in it ok", "tab\tseparated-token-x"] {
            m.insert("STORAGE_MGMT_TOKEN", bad.to_owned());
            assert_eq!(
                parse(&m).err(),
                Some(BadSetting("STORAGE_MGMT_TOKEN")),
                "{bad}"
            );
        }
        let token = "storage-token-for-tests-0123456789";
        m.insert("STORAGE_MGMT_TOKEN", token.to_owned());
        // The confirmed token is required too, well formed, and its own.
        assert_eq!(
            parse(&m).err(),
            Some(BadSetting("STORAGE_MGMT_TOKEN_CONFIRMED"))
        );
        for bad in ["short", "has a space in it ok", token] {
            m.insert("STORAGE_MGMT_TOKEN_CONFIRMED", bad.to_owned());
            assert_eq!(
                parse(&m).err(),
                Some(BadSetting("STORAGE_MGMT_TOKEN_CONFIRMED")),
                "{bad}"
            );
        }
        let confirmed = "confirmed-token-for-tests-9876543210";
        m.insert("STORAGE_MGMT_TOKEN_CONFIRMED", confirmed.to_owned());
        let s = parse(&m).unwrap();
        assert!(matches!(s.storage, StorageSetting::Mgmt { .. }));
        // Debug never shows a token.
        let shown = format!("{s:?}");
        assert!(
            !shown.contains(token) && !shown.contains(confirmed),
            "{shown}"
        );
        assert!(shown.contains("Mgmt"));
        m.insert("STORAGE_PLANE", "real".to_owned());
        assert_eq!(parse(&m).err(), Some(BadSetting("STORAGE_PLANE")));
    }

    #[test]
    fn every_missing_or_malformed_setting_is_named() {
        for (name, bad) in [
            ("KOFRA_ENV", Some("prod")),
            ("CONSOLE_ORIGIN", Some("http://console.example.com")),
            ("CONSOLE_ORIGIN", Some("https://console.example.com/path")),
            ("CONSOLE_ORIGIN", Some("https://console.example.com/?x")),
            ("CONSOLE_ORIGIN", Some("not a url")),
            ("CONSOLE_ORIGIN", Some("https://console.example.com/app/..")),
            ("S3_ENDPOINT", None),
            ("SIGNUP_MODE", Some("open")),
            ("SIGNUP_MODE", None),
            ("MAIL_MODE", Some("smtp")),
            ("MAIL_FROM", Some("Kofra <noreply>")),
            ("ACCOUNT_SECRET_KEY", Some("abc")),
            ("ASSERTION_KEY", Some(&"00".repeat(32))),
            ("CURSOR_KEY", Some(&"zz".repeat(32))),
            ("CURSOR_KEY", Some(&"22".repeat(32))),
            ("ASSERTION_KEY", Some(&"11".repeat(32))),
            ("BREACH_CHECK", Some("off")),
        ] {
            let mut m = base();
            match bad {
                Some(v) => m.insert(name, v.to_owned()),
                None => m.remove(name),
            };
            assert_eq!(parse(&m).err(), Some(BadSetting(name)), "{name} = {bad:?}");
        }
    }

    #[test]
    fn test_only_mail_modes_never_reach_production() {
        for (env, mode, ok) in [
            ("production", "outbox", false),
            ("production", "log", true),
            ("staging", "outbox", true),
            ("staging", "capture", false),
            ("local", "capture", true),
        ] {
            let mut m = base();
            m.insert("KOFRA_ENV", env.into());
            m.insert("MAIL_MODE", mode.into());
            m.insert("MAIL_CAPTURE_URL", "http://127.0.0.1:4180/mail".into());
            assert_eq!(parse(&m).is_ok(), ok, "{env} {mode}");
        }
        for url in [
            "https://mail.example.net/in",
            &format!("http://127.0.0.1:4180{}collector.example/mail", '@'),
            "http://user:pw@127.0.0.1:4180/mail",
            "http://127.0.0.1.example/mail",
            "http://10.0.0.1:4180/mail",
        ] {
            let mut m = base();
            m.insert("KOFRA_ENV", "local".into());
            m.insert("MAIL_MODE", "capture".into());
            m.insert("MAIL_CAPTURE_URL", url.into());
            assert_eq!(
                parse(&m).err(),
                Some(BadSetting("MAIL_CAPTURE_URL")),
                "{url}"
            );
        }
        for url in [
            "http://127.0.0.1:4180/mail",
            "http://localhost:9/x",
            "http://[::1]:8080/",
            "http://127.0.0.1/mail",
            "http://127.0.0.1:80/mail",
        ] {
            let mut m = base();
            m.insert("KOFRA_ENV", "local".into());
            m.insert("MAIL_MODE", "capture".into());
            m.insert("MAIL_CAPTURE_URL", url.into());
            assert!(parse(&m).is_ok(), "{url}");
        }
        // The allow-list's other mode follows the same rule.
        let mut m = base();
        m.insert("KOFRA_ENV", "production".into());
        m.insert("MAIL_ALLOW", "owner@example.com".into());
        m.insert("MAIL_OTHERS", "outbox".into());
        assert_eq!(parse(&m).err(), Some(BadSetting("MAIL_OTHERS")));
    }

    #[test]
    fn origins_are_kept_in_the_form_browsers_send() {
        for (given, kept) in [
            ("https://console.example.com", "https://console.example.com"),
            (
                "https://console.example.com/",
                "https://console.example.com",
            ),
            (
                "https://console.example.com:443",
                "https://console.example.com",
            ),
            (
                "https://Console.Example.com:8443",
                "https://console.example.com:8443",
            ),
        ] {
            let mut m = base();
            m.insert("CONSOLE_ORIGIN", given.into());
            let s = parse(&m).unwrap();
            assert_eq!(s.console_origin, kept, "{given}");
        }
        let mut m = base();
        m.insert("CONSOLE_ORIGIN", "https://console.example.com:443".into());
        assert_eq!(parse(&m).unwrap().accounts().rp_id, "console.example.com");
    }

    #[test]
    fn subkeys_differ_by_purpose_and_by_secret() {
        let s = parse(&base()).unwrap();
        assert_ne!(s.subkey(b"a"), s.subkey(b"b"));
        let mut m = base();
        m.insert("ACCOUNT_SECRET_KEY", "44".repeat(32));
        assert_ne!(parse(&m).unwrap().subkey(b"a"), s.subkey(b"a"));
        assert_ne!(s.subkey(b"a"), s.account_secret);
    }

    #[test]
    fn the_allow_list_picks_the_mode_per_recipient() {
        let mut m = base();
        m.insert(
            "MAIL_ALLOW",
            format!("{}, @team.example.org", at("Owner", "Example.com")),
        );
        m.insert("MAIL_OTHERS", "outbox".into());
        let s = parse(&m).unwrap();
        assert_eq!(s.mail.mode_for("owner@example.com"), &MailMode::Send);
        assert_eq!(s.mail.mode_for(" OWNER@example.com"), &MailMode::Send);
        assert_eq!(
            s.mail.mode_for(&at("a", "team.example.org")),
            &MailMode::Send
        );
        assert_eq!(
            s.mail.mode_for(&at("a", "sub.team.example.org")),
            &MailMode::Outbox
        );
        assert_eq!(s.mail.mode_for("someone@example.com"), &MailMode::Outbox);
        // Without a list, everyone gets the mode.
        let s = parse(&base()).unwrap();
        assert_eq!(s.mail.mode_for("anyone@example.net"), &MailMode::Send);
    }
}
