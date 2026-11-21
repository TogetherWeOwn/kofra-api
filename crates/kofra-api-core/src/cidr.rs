//! Client address allow-lists: single addresses and CIDR blocks.

use std::{fmt, net::IpAddr};

/// An address block. A single address is a block of its full length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRange {
    addr: IpAddr,
    prefix: u8,
}

impl IpRange {
    /// The block in `s` (`203.0.113.7`, `203.0.113.0/24`, `2001:db8::/32`).
    /// Host bits below the prefix must be zero, so each block has one
    /// spelling.
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                (a.parse::<IpAddr>().ok()?, Some(p.parse::<u8>().ok()?))
            }
            None => (s.parse::<IpAddr>().ok()?, None),
        };
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return None;
        }
        let range = Self { addr, prefix };
        if range.network() != bits(addr) {
            return None;
        }
        Some(range)
    }

    fn width(self) -> u32 {
        if self.addr.is_ipv4() { 32 } else { 128 }
    }

    fn mask(self) -> u128 {
        let w = self.width();
        let host = w - u32::from(self.prefix);
        let all = if w == 32 {
            u128::from(u32::MAX)
        } else {
            u128::MAX
        };
        if host >= 128 {
            0
        } else {
            all & !((1u128 << host) - 1)
        }
    }

    fn network(self) -> u128 {
        bits(self.addr) & self.mask()
    }

    /// Whether `ip` is inside the block. IPv4-mapped IPv6 addresses are
    /// compared as IPv4.
    pub fn contains(self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        if ip.is_ipv4() != self.addr.is_ipv4() {
            return false;
        }
        bits(ip) & self.mask() == self.network()
    }

    /// Whether the whole block lies inside `outer`.
    pub fn within(self, outer: Self) -> bool {
        self.addr.is_ipv4() == outer.addr.is_ipv4()
            && self.prefix >= outer.prefix
            && outer.contains(self.addr)
    }
}

impl fmt::Display for IpRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let full = if self.addr.is_ipv4() { 32 } else { 128 };
        if self.prefix == full {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix)
        }
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn bits(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(a) => u128::from(u32::from(a)),
        IpAddr::V6(a) => u128::from(a),
    }
}

/// Whether `ip` is inside any block of `list`. An unknown client address is
/// never inside.
pub fn allowed(list: &[IpRange], ip: Option<IpAddr>) -> bool {
    ip.is_some_and(|ip| list.iter().any(|r| r.contains(ip)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("ip")
    }

    #[test]
    fn blocks_parse_in_one_spelling_and_contain_their_addresses() {
        let r = IpRange::parse("203.0.113.0/24").expect("v4");
        assert!(r.contains(ip("203.0.113.200")));
        assert!(!r.contains(ip("203.0.114.1")));
        assert!(r.contains(ip("::ffff:203.0.113.9")));
        assert!(IpRange::parse("203.0.113.1/24").is_none(), "host bits set");
        assert!(IpRange::parse("203.0.113.0/33").is_none());
        assert!(IpRange::parse("203.0.113.0/").is_none());
        assert!(IpRange::parse("203.0.113.0/+8").is_none());
        let all = IpRange::parse("0.0.0.0/0").expect("all v4");
        assert!(all.contains(ip("198.51.100.1")));
        assert!(!all.contains(ip("2001:db8::1")));
        let v6 = IpRange::parse("2001:db8::/32").expect("v6");
        assert!(v6.contains(ip("2001:db8:1::5")));
        assert!(!v6.contains(ip("2001:db9::1")));
        let one = IpRange::parse("198.51.100.7").expect("single");
        assert_eq!(one.to_string(), "198.51.100.7");
        assert!(one.contains(ip("198.51.100.7")));
        assert!(!one.contains(ip("198.51.100.8")));
        assert!(
            IpRange::parse("::/0")
                .expect("all v6")
                .contains(ip("2001:db8::1"))
        );
    }

    #[test]
    fn within_compares_blocks() {
        let outer = IpRange::parse("203.0.113.0/24").expect("outer");
        assert!(
            IpRange::parse("203.0.113.128/25")
                .expect("inner")
                .within(outer)
        );
        assert!(IpRange::parse("203.0.113.7").expect("one").within(outer));
        assert!(
            !IpRange::parse("203.0.112.0/23")
                .expect("wider")
                .within(outer)
        );
        assert!(!IpRange::parse("2001:db8::/32").expect("v6").within(outer));
        assert!(!allowed(&[outer], None));
    }
}
