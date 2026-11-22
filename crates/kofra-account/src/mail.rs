//! The messages the service sends. Plain sentences, no images, no tracking,
//! and no word about how or where files are stored.

use crate::ports::Mail;

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// One message: a greeting, paragraphs, an optional button link, and the
/// footer. The HTML is the same text, escaped.
fn build(to: &str, subject: &str, name: &str, paras: &[&str], link: Option<(&str, &str)>) -> Mail {
    let greeting = if name.trim().is_empty() {
        "Hello,".to_owned()
    } else {
        format!("Hello {},", name.trim())
    };
    let footer = "You get this message because of your Kofra account. If it was not you, you can ignore it, or reply to reach us.";
    let mut text = format!("{greeting}\n\n");
    let mut html = format!(
        "<!doctype html><html><body style=\"font-family:system-ui,sans-serif;line-height:1.5;color:#111\"><p>{}</p>",
        escape(&greeting)
    );
    for p in paras {
        text.push_str(p);
        text.push_str("\n\n");
        html.push_str(&format!("<p>{}</p>", escape(p)));
    }
    if let Some((label, url)) = link {
        text.push_str(&format!("{label}:\n{url}\n\n"));
        html.push_str(&format!(
            "<p><a href=\"{}\" style=\"display:inline-block;padding:10px 16px;background:#1d4ed8;color:#fff;text-decoration:none;border-radius:4px\">{}</a></p><p style=\"font-size:13px;color:#555\">Or open this address: {}</p>",
            escape(url),
            escape(label),
            escape(url)
        ));
    }
    text.push_str("Kofra\n\n");
    text.push_str(footer);
    text.push('\n');
    html.push_str(&format!(
        "<p>Kofra</p><p style=\"font-size:13px;color:#555\">{}</p></body></html>",
        escape(footer)
    ));
    Mail {
        to: to.to_owned(),
        subject: subject.to_owned(),
        text,
        html,
    }
}

/// Confirm the address after sign-up.
pub fn verify(to: &str, name: &str, url: &str) -> Mail {
    build(
        to,
        "Confirm your email address",
        name,
        &[
            "Confirm your email address to finish creating your Kofra account. The link works for 24 hours.",
        ],
        Some(("Confirm email address", url)),
    )
}

/// Someone signed up with an address that has an account.
pub fn already_registered(to: &str, name: &str, url: &str) -> Mail {
    build(
        to,
        "You already have a Kofra account",
        name,
        &[
            "Someone tried to create a Kofra account with this address, which already has one. If it was you, sign in, or reset your password if you forgot it.",
        ],
        Some(("Sign in", url)),
    )
}

/// Reset the password.
pub fn reset(to: &str, name: &str, url: &str) -> Mail {
    build(
        to,
        "Reset your Kofra password",
        name,
        &[
            "Use the link below to choose a new password. It works for 30 minutes and only once. If you did not ask for this, ignore this message: your password stays as it is.",
        ],
        Some(("Choose a new password", url)),
    )
}

/// Confirm a new address.
pub fn email_change(to: &str, name: &str, url: &str) -> Mail {
    build(
        to,
        "Confirm your new email address",
        name,
        &[
            "Confirm this address to make it the sign-in address of your Kofra account. The link works for 24 hours.",
        ],
        Some(("Confirm new address", url)),
    )
}

/// The new address is already in use.
pub fn email_taken(to: &str) -> Mail {
    build(
        to,
        "This address already has a Kofra account",
        "",
        &[
            "Someone asked to move a Kofra account to this address, but it already belongs to another account. Nothing was changed.",
        ],
        None,
    )
}

/// A security notice to the account's address.
pub fn notice(to: &str, name: &str, what: &str) -> Mail {
    build(
        to,
        "Security notice for your Kofra account",
        name,
        &[
            what,
            "If this was not you, reset your password now and contact us.",
        ],
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_escape_html_and_carry_the_link_in_both_parts() {
        let m = verify(
            "ada@example.com",
            "<Ada>",
            "https://console.example/verify?token=abc&x=1",
        );
        assert!(m.text.contains("Hello <Ada>,"));
        assert!(m.html.contains("Hello &lt;Ada&gt;,"));
        assert!(!m.html.contains("<Ada>"));
        assert!(
            m.text
                .contains("https://console.example/verify?token=abc&x=1")
        );
        assert!(m.html.contains("token=abc&amp;x=1"));
    }
}
