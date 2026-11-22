//! The Worker's settings, read once per request from its variables and
//! secrets. Parsing is a pure function of a lookup, so it is tested
//! natively. A setting that is missing or malformed refuses the request
//! (fail closed); the error names the setting, never its value.

use kofra_account::SignupMode;

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
    /// Sender address, e.g. `noreply@mail.kofra.app`.
    pub from: String,
    /// Sender name.
    pub from_name: String,
    /// Reply-To, when set.
    pub reply_to: Option<String>,
}

impl MailSettings {
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
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("deployment", &self.deployment)
            .field("console_origin", &self.console_origin)
            .field("signup", &self.signup)
            .field("mail", &self.mail.mode)
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

fn https_origin(v: &str, local: bool) -> bool {
    let rest = v
        .strip_prefix("https://")
        .or_else(|| local.then(|| v.strip_prefix("http://")).flatten());
    rest.is_some_and(|h| {
        !h.is_empty()
            && !h.contains('/')
            && !h.contains('?')
            && !h.contains('#')
            && !h.contains('@')
    })
}

fn loopback_url(v: &str) -> bool {
    ["http://127.0.0.1:", "http://localhost:", "http://[::1]:"]
        .iter()
        .any(|p| v.starts_with(p))
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
            .filter(|v| https_origin(v, local))
            .ok_or(BadSetting("CONSOLE_ORIGIN"))?;
        let s3_endpoint = get("S3_ENDPOINT")
            .filter(|v| https_origin(v, local))
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
        let account_secret = key(&get, "ACCOUNT_SECRET_KEY")?;
        let console_key = key(&get, "ASSERTION_KEY")?;
        let cursor_key = key(&get, "CURSOR_KEY")?;
        if account_secret == console_key
            || account_secret == cursor_key
            || console_key == cursor_key
        {
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
        })
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

    fn base() -> HashMap<&'static str, String> {
        HashMap::from([
            ("KOFRA_ENV", "staging".to_owned()),
            ("CONSOLE_ORIGIN", "https://console.example.com".to_owned()),
            ("S3_ENDPOINT", "https://s3.example.com".to_owned()),
            ("SIGNUP_MODE", "invite".to_owned()),
            ("MAIL_MODE", "send".to_owned()),
            ("MAIL_FROM", "noreply@mail.example.com".to_owned()),
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
    fn every_missing_or_malformed_setting_is_named() {
        for (name, bad) in [
            ("KOFRA_ENV", Some("prod")),
            ("CONSOLE_ORIGIN", Some("http://console.example.com")),
            ("CONSOLE_ORIGIN", Some("https://console.example.com/path")),
            ("S3_ENDPOINT", None),
            ("SIGNUP_MODE", Some("open")),
            ("SIGNUP_MODE", None),
            ("MAIL_MODE", Some("smtp")),
            ("MAIL_FROM", Some("Kofra <noreply@mail.example.com>")),
            ("ACCOUNT_SECRET_KEY", Some("abc")),
            ("ASSERTION_KEY", Some(&"00".repeat(32))),
            ("CURSOR_KEY", Some(&"zz".repeat(32))),
            ("CURSOR_KEY", Some(&"22".repeat(32))),
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
        let mut m = base();
        m.insert("KOFRA_ENV", "local".into());
        m.insert("MAIL_MODE", "capture".into());
        m.insert("MAIL_CAPTURE_URL", "https://mail.example.net/in".into());
        assert_eq!(parse(&m).err(), Some(BadSetting("MAIL_CAPTURE_URL")));
        // The allow-list's other mode follows the same rule.
        let mut m = base();
        m.insert("KOFRA_ENV", "production".into());
        m.insert("MAIL_ALLOW", "owner@example.com".into());
        m.insert("MAIL_OTHERS", "outbox".into());
        assert_eq!(parse(&m).err(), Some(BadSetting("MAIL_OTHERS")));
    }

    #[test]
    fn the_allow_list_picks_the_mode_per_recipient() {
        let mut m = base();
        m.insert("MAIL_ALLOW", "Owner@Example.com, @team.example.org".into());
        m.insert("MAIL_OTHERS", "outbox".into());
        let s = parse(&m).unwrap();
        assert_eq!(s.mail.mode_for("owner@example.com"), &MailMode::Send);
        assert_eq!(s.mail.mode_for(" OWNER@example.com"), &MailMode::Send);
        assert_eq!(s.mail.mode_for("a@team.example.org"), &MailMode::Send);
        assert_eq!(s.mail.mode_for("a@sub.team.example.org"), &MailMode::Outbox);
        assert_eq!(s.mail.mode_for("someone@example.com"), &MailMode::Outbox);
        // Without a list, everyone gets the mode.
        let s = parse(&base()).unwrap();
        assert_eq!(s.mail.mode_for("anyone@example.net"), &MailMode::Send);
    }
}
