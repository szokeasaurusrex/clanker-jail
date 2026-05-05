use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Result, bail};

#[must_use]
pub fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_blocked_ipv4(ip),
        IpAddr::V6(ip) => is_blocked_ipv6(ip),
    }
}

/// Rejects socket addresses that do not satisfy the public egress policy.
///
/// # Errors
///
/// Returns an error when `addr` is blocked by policy.
pub fn validate_socket_addr(addr: SocketAddr) -> Result<()> {
    if is_blocked_ip(addr.ip()) {
        bail!("blocked destination address {addr}");
    }
    Ok(())
}

fn is_blocked_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
}

fn is_blocked_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{is_blocked_ip, validate_socket_addr};

    #[test]
    fn blocks_ipv4_ranges() {
        for ip in [
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 0, 1),
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::new(192, 0, 2, 1),
        ] {
            assert!(is_blocked_ip(IpAddr::V4(ip)), "{ip} should be blocked");
        }
    }

    #[test]
    fn blocks_ipv6_ranges() {
        for ip in [
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::UNSPECIFIED,
            "fc00::1".parse().unwrap(),
            "fd00::1".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            "ff02::1".parse().unwrap(),
        ] {
            assert!(is_blocked_ip(IpAddr::V6(ip)), "{ip} should be blocked");
        }
    }

    #[test]
    fn allows_public_addresses() {
        for ip in [
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            IpAddr::V6("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()),
        ] {
            assert!(!is_blocked_ip(ip), "{ip} should be allowed");
            validate_socket_addr(SocketAddr::new(ip, 443)).unwrap();
        }
    }
}
