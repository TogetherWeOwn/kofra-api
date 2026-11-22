//! The account service's `Mailer` on the Worker.
//!
//! The port must not wait for delivery on the request path, so every
//! message is handed to `waitUntil` and `send` returns at once: sending
//! takes the same short time whoever the recipient is. Outcomes are logged
//! as one line with the message kind, the mode and a short hash of the
//! address; never the address, the subject's variable parts, or the body
//! (it holds links that act as credentials).

use std::rc::Rc;

use kofra_account::ports::{Mail, Mailer, PortResult};
use kofra_store::{Db, Stmt, params};
use sha2::{Digest, Sha256};
use worker::{Context, Env};

use crate::config::{MailMode, MailSettings};
use crate::d1::D1Db;

/// A short, stable label for an address in logs: the first 8 hex digits of
/// its SHA-256. Enough to tell two recipients apart in one incident.
pub fn address_tag(to: &str) -> String {
    let h = Sha256::digest(to.trim().to_ascii_lowercase().as_bytes());
    h.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// The message kind for logs: its subject, which the account service
/// writes from fixed text (no names, no addresses).
pub fn kind(mail: &Mail) -> &str {
    &mail.subject
}

/// The JSON a capture sink receives (local e2e only).
pub fn capture_body(mail: &Mail) -> String {
    serde_json::json!({
        "to": mail.to,
        "subject": mail.subject,
        "text": mail.text,
    })
    .to_string()
}

/// Mail on the Worker: the `EMAIL` binding, the log, the outbox table, or
/// a loopback capture sink, per recipient (`MailSettings::mode_for`).
pub struct WorkerMailer {
    settings: MailSettings,
    env: Env,
    /// The request's context, whose `waitUntil` carries the delivery; none
    /// in the cron, which delivers inline.
    ctx: Option<Rc<Context>>,
    db: Rc<D1Db>,
}

impl WorkerMailer {
    /// A mailer for one request (`ctx`) or for the cron (`None`).
    pub fn new(settings: MailSettings, env: Env, ctx: Option<Rc<Context>>, db: Rc<D1Db>) -> Self {
        Self {
            settings,
            env,
            ctx,
            db,
        }
    }
}

impl Mailer for WorkerMailer {
    async fn send(&self, mail: &Mail) -> PortResult<()> {
        let mode = self.settings.mode_for(&mail.to).clone();
        let mail = mail.clone();
        let tag = address_tag(&mail.to);
        let settings = self.settings.clone();
        let env = self.env.clone();
        let db = Rc::clone(&self.db);
        let work = async move {
            let outcome = deliver(&mode, &settings, &env, &db, &mail).await;
            let label = match &mode {
                MailMode::Send => "send",
                MailMode::Log => "log",
                MailMode::Outbox => "outbox",
                MailMode::Capture(_) => "capture",
            };
            match outcome {
                Ok(()) => worker::console_log!("mail: {label} ok kind={:?} to={tag}", kind(&mail)),
                Err(class) => worker::console_error!(
                    "mail: {label} failed ({class}) kind={:?} to={tag}",
                    kind(&mail)
                ),
            }
        };
        match &self.ctx {
            Some(ctx) => ctx.wait_until(work),
            None => work.await,
        }
        Ok(())
    }
}

async fn deliver(
    mode: &MailMode,
    settings: &MailSettings,
    env: &Env,
    db: &D1Db,
    mail: &Mail,
) -> Result<(), &'static str> {
    match mode {
        MailMode::Log => Ok(()),
        MailMode::Send => {
            use worker::{EmailAddress, SendEmail, SendEmailBuilder};
            let binding: SendEmail = env.get_binding("EMAIL").map_err(|_| "no EMAIL binding")?;
            let from = EmailAddress::new(&settings.from_name, &settings.from);
            let msg =
                SendEmailBuilder::new_with_email_address_and_str(&from, &mail.to, &mail.subject);
            msg.set_text(&mail.text);
            msg.set_html(&mail.html);
            if let Some(r) = &settings.reply_to {
                msg.set_reply_to(r);
            }
            binding
                .send_with_builder(&msg)
                .await
                .map(drop)
                .map_err(|_| "binding refused")
        }
        MailMode::Outbox => db
            .run(&Stmt::new(
                "INSERT INTO account_mail_outbox (to_addr, subject, text_body, created_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    mail.to.trim().to_ascii_lowercase(),
                    &mail.subject,
                    &mail.text,
                    worker::Date::now().as_millis()
                ],
            ))
            .await
            .map(drop)
            .map_err(|_| "outbox write failed"),
        MailMode::Capture(url) => {
            let mut init = worker::RequestInit::new();
            init.with_method(worker::Method::Post);
            let headers = worker::Headers::new();
            headers
                .set("Content-Type", "application/json")
                .map_err(|_| "headers")?;
            init.with_headers(headers);
            init.with_body(Some(capture_body(mail).into()));
            let req = worker::Request::new_with_init(url, &init).map_err(|_| "request")?;
            let resp = worker::Fetch::Request(req)
                .send()
                .await
                .map_err(|_| "capture unreachable")?;
            if resp.status_code() / 100 == 2 {
                Ok(())
            } else {
                Err("capture refused")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logs_name_addresses_by_a_short_hash_only() {
        let tag = address_tag("Owner@Example.com ");
        assert_eq!(tag, address_tag("owner@example.com"));
        assert_eq!(tag.len(), 8);
        assert!(!tag.contains('@'));
        assert_ne!(tag, address_tag("other@example.com"));
    }

    #[test]
    fn the_capture_body_has_no_html() {
        let m = Mail {
            to: "a@example.com".into(),
            subject: "Confirm your email address".into(),
            text: "link".into(),
            html: "<p>link</p>".into(),
        };
        let v: serde_json::Value = serde_json::from_str(&capture_body(&m)).unwrap();
        assert_eq!(v["to"], "a@example.com");
        assert!(v.get("html").is_none());
    }
}
