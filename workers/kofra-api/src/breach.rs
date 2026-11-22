//! The breached-password check: the k-anonymity range query of Have I Been
//! Pwned. Only the first five hex digits of the password's SHA-1 leave the
//! Worker; the answer is padded (`Add-Padding`), so its size does not tell
//! which range was asked. Two seconds at most: on a timeout or any other
//! failure the port answers an error and the service accepts the password
//! and logs the event (accounts design §5.1).

use std::time::Duration;

use futures_util::future::{Either, select};
use kofra_account::ports::{BreachCheck, PortError, PortResult};
use sha1::{Digest, Sha1};

/// Whether `body` (lines `SUFFIX:COUNT`) lists `suffix` with a count above
/// zero. Padding lines have a count of zero.
pub fn listed(body: &str, suffix: &str) -> bool {
    body.lines().any(|line| {
        let mut parts = line.trim().splitn(2, ':');
        let (Some(s), Some(n)) = (parts.next(), parts.next()) else {
            return false;
        };
        s.eq_ignore_ascii_case(suffix) && n.trim().parse::<u64>().is_ok_and(|n| n > 0)
    })
}

/// The range prefix (5 hex digits) and the suffix (35) of a password.
pub fn split_hash(password: &str) -> (String, String) {
    let h = Sha1::digest(password.as_bytes());
    let hex: String = h.iter().map(|b| format!("{b:02X}")).collect();
    (hex[..5].to_owned(), hex[5..].to_owned())
}

/// The check, or no check (local tests only).
pub struct Breach {
    /// Off: every password passes.
    pub enabled: bool,
}

const TIMEOUT: Duration = Duration::from_secs(2);

impl BreachCheck for Breach {
    async fn breached(&self, password: &str) -> PortResult<bool> {
        if !self.enabled {
            return Ok(false);
        }
        let (prefix, suffix) = split_hash(password);
        let url = format!("https://api.pwnedpasswords.com/range/{prefix}");
        let fetch = Box::pin(async move {
            let headers = worker::Headers::new();
            headers.set("Add-Padding", "true").ok()?;
            headers.set("User-Agent", "kofra-api").ok()?;
            let mut init = worker::RequestInit::new();
            init.with_headers(headers);
            let req = worker::Request::new_with_init(&url, &init).ok()?;
            let mut resp = worker::Fetch::Request(req).send().await.ok()?;
            if resp.status_code() != 200 {
                return None;
            }
            resp.text().await.ok()
        });
        let timer = Box::pin(worker::Delay::from(TIMEOUT));
        match select(fetch, timer).await {
            Either::Left((Some(body), _)) => Ok(listed(&body, &suffix)),
            _ => Err(PortError::Unavailable { retry_after: 1 }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_range_answer_is_read_line_by_line() {
        let (prefix, suffix) = split_hash("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:10437277\r\n";
        assert!(listed(body, &suffix));
        assert!(!listed(body, "0000000000000000000000000000000000A"));
        // A padding line (count 0) is not a breach.
        assert!(!listed("1E4C9B93F3F0682250B6CF8331B7EE68FD8:0\n", &suffix));
        assert!(!listed("garbage", &suffix));
    }
}
