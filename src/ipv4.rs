//! IPv4 literals and CIDR expansion used by IP import.
//!
//! Port `--ip`, domain `bind_ip`, and DNS write-back still require a single
//! IPv4 address. Only IP asset import expands CIDR networks into host rows.
//! Prefix `/0` through `/32` are accepted; the caller owns expansion size.

use std::net::Ipv4Addr;

use crate::models::AssetPage;

/// Inclusive IPv4 host range after network-bit masking.
struct Ipv4Range {
    start: u32,
    count: u64,
}

/// Parse one IPv4 address or CIDR network into a host range.
///
/// Host bits in the address are masked off, so `10.0.0.1/24` expands the
/// containing `10.0.0.0/24` network. The range includes the network and
/// broadcast addresses. Any prefix in `0..=32` is accepted.
///
/// # Arguments
/// - `value`: IPv4 literal or `a.b.c.d/prefix` text.
///
/// # Returns
/// Start address as `u32` plus host count as `u64`.
///
/// # Errors
/// Returns an error when `value` is empty, not IPv4, or has a prefix outside
/// `0..=32`.
///
/// # Examples
/// ```text
/// let range = parse_ipv4_range("10.0.0.0/30")?;
/// assert_eq!(range.count, 4);
/// ```
fn parse_ipv4_range(value: &str) -> anyhow::Result<Ipv4Range> {
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "ip value must not be empty");
    if let Ok(addr) = value.parse::<Ipv4Addr>() {
        return Ok(Ipv4Range {
            start: u32::from(addr),
            count: 1,
        });
    }
    let Some((addr_text, prefix_text)) = value.split_once('/') else {
        anyhow::bail!("only IPv4 addresses or CIDR networks are supported: {value}");
    };
    let addr: Ipv4Addr = addr_text.trim().parse().map_err(|_| {
        anyhow::anyhow!("only IPv4 addresses or CIDR networks are supported: {value}")
    })?;
    let prefix: u8 = prefix_text
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid IPv4 CIDR prefix: {value}"))?;
    anyhow::ensure!(prefix <= 32, "invalid IPv4 CIDR prefix: {value}");
    let host_bits = 32u32 - u32::from(prefix);
    let count = 1u64 << host_bits;
    let mask = if host_bits == 0 {
        u32::MAX
    } else if host_bits >= 32 {
        0
    } else {
        u32::MAX << host_bits
    };
    Ok(Ipv4Range {
        start: u32::from(addr) & mask,
        count,
    })
}

/// Expand one IPv4 address or CIDR into canonical host addresses.
///
/// # Arguments
/// - `value`: IPv4 literal or CIDR network.
///
/// # Returns
/// Host addresses in numeric order, including network and broadcast.
///
/// # Errors
/// Returns an error when [`parse_ipv4_range`] rejects `value`.
///
/// # Examples
/// ```text
/// let hosts = expand_ipv4_target("10.0.0.0/30")?;
/// assert_eq!(hosts, ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]);
/// ```
pub(crate) fn expand_ipv4_target(value: &str) -> anyhow::Result<Vec<String>> {
    let range = parse_ipv4_range(value)?;
    let mut hosts =
        Vec::with_capacity(usize::try_from(range.count).expect("CIDR host count fits in usize"));
    for offset in 0..range.count {
        let offset = u32::try_from(offset).expect("CIDR host offset fits in u32");
        let host = range
            .start
            .checked_add(offset)
            .expect("CIDR host offset fits in u32");
        hosts.push(Ipv4Addr::from(host).to_string());
    }
    Ok(hosts)
}

/// Expand a list of IPv4 addresses and CIDR networks.
///
/// Blank entries are skipped. Each remaining value is expanded independently
/// and concatenated in input order.
///
/// # Arguments
/// - `values`: Raw import lines.
///
/// # Returns
/// Flattened host-address list after CIDR expansion.
///
/// # Errors
/// Returns an error when any non-blank value is not an IPv4 address or CIDR
/// network.
///
/// # Examples
/// ```text
/// let hosts = expand_ipv4_targets(&["10.0.0.8".into(), "10.0.0.0/30".into()])?;
/// ```
pub(crate) fn expand_ipv4_targets(values: &[String]) -> anyhow::Result<Vec<String>> {
    let mut hosts = Vec::new();
    for value in values {
        if value.trim().is_empty() {
            continue;
        }
        hosts.extend(expand_ipv4_target(value)?);
    }
    Ok(hosts)
}

/// Return one page of hosts for an IPv4 address or CIDR network.
///
/// Used by the read-only MCP `expand_ipv4_cidr` tool. Hosts are not written
/// to the database.
///
/// # Arguments
/// - `value`: IPv4 literal or CIDR network.
/// - `offset`: Number of hosts to skip.
/// - `limit`: Page size.
///
/// # Returns
/// [`AssetPage`] of dotted IPv4 strings.
///
/// # Errors
/// Returns an error when [`parse_ipv4_range`] rejects `value`.
///
/// # Examples
/// ```text
/// let page = page_ipv4_target("10.0.0.0/24", 0, 50)?;
/// assert_eq!(page.total, 256);
/// ```
pub(crate) fn page_ipv4_target(
    value: &str,
    offset: usize,
    limit: usize,
) -> anyhow::Result<AssetPage<String>> {
    let range = parse_ipv4_range(value)?;
    let total = i64::try_from(range.count).expect("CIDR host count fits in i64");
    let count = usize::try_from(range.count).expect("CIDR host count fits in usize");
    let start_index = offset.min(count);
    let end_index = start_index.saturating_add(limit).min(count);
    let mut items = Vec::with_capacity(end_index.saturating_sub(start_index));
    for index in start_index..end_index {
        let index = u32::try_from(index).expect("paged CIDR index fits in u32");
        let host = range
            .start
            .checked_add(index)
            .expect("paged CIDR host offset fits in u32");
        items.push(Ipv4Addr::from(host).to_string());
    }
    Ok(AssetPage::new(items, total, offset, limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `/30` expands four hosts including network and broadcast.
    #[test]
    fn expands_slash30_including_network_and_broadcast() {
        assert_eq!(
            expand_ipv4_target("10.0.0.0/30").unwrap(),
            ["10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]
        );
    }

    /// Host bits are masked so `10.0.0.5/30` expands `10.0.0.4/30`.
    #[test]
    fn masks_host_bits_before_expanding() {
        assert_eq!(
            expand_ipv4_target("10.0.0.5/30").unwrap(),
            ["10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7"]
        );
        let slash24 = expand_ipv4_target("10.0.0.1/24").unwrap();
        assert_eq!(slash24.len(), 256);
        assert_eq!(slash24[0], "10.0.0.0");
        assert_eq!(slash24[255], "10.0.0.255");
    }

    /// A literal IPv4 address stays a single host.
    #[test]
    fn literal_ipv4_is_one_host() {
        assert_eq!(expand_ipv4_target(" 10.0.0.8 ").unwrap(), ["10.0.0.8"]);
    }

    /// Prefix `/0` through `/32` are counted without rejecting large networks.
    #[test]
    fn accepts_every_ipv4_prefix_length() {
        assert_eq!(parse_ipv4_range("192.0.2.1/32").unwrap().count, 1);
        assert_eq!(parse_ipv4_range("10.0.0.0/16").unwrap().count, 65_536);
        assert_eq!(parse_ipv4_range("10.0.0.0/15").unwrap().count, 131_072);
        assert_eq!(parse_ipv4_range("0.0.0.0/0").unwrap().count, 1u64 << 32);
    }

    /// IPv6 and empty values are rejected. Large IPv4 CIDR is not.
    #[test]
    fn rejects_non_ipv4_values() {
        let ipv6 = expand_ipv4_target("2001:db8::1").unwrap_err().to_string();
        assert!(ipv6.contains("IPv4"));
        let empty = expand_ipv4_target("").unwrap_err().to_string();
        assert!(empty.contains("empty"));
        assert!(parse_ipv4_range("10.0.0.0/15").is_ok());
    }

    /// Blank import lines are skipped; remaining CIDR and IPs are flattened.
    #[test]
    fn skips_blank_lines_when_expanding_a_list() {
        let hosts =
            expand_ipv4_targets(&[" ".into(), "10.0.0.8".into(), "10.0.0.0/30".into()]).unwrap();
        assert_eq!(
            hosts,
            ["10.0.0.8", "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"]
        );
    }

    /// MCP paging returns a window without materializing the whole CIDR.
    #[test]
    fn pages_cidr_hosts() {
        let page = page_ipv4_target("10.0.0.0/24", 50, 50).unwrap();
        assert_eq!(page.total, 256);
        assert_eq!(page.items.len(), 50);
        assert_eq!(page.items[0], "10.0.0.50");
        assert_eq!(page.items[49], "10.0.0.99");
        assert!(page.has_more);
        assert_eq!(page.next_offset, Some(100));
    }

    /// `/0` can be paged without allocating the full address space.
    #[test]
    fn pages_slash0_without_expanding_all_hosts() {
        let page = page_ipv4_target("0.0.0.0/0", 0, 2).unwrap();
        assert_eq!(page.total, 1 << 32);
        assert_eq!(page.items, ["0.0.0.0", "0.0.0.1"]);
        assert!(page.has_more);
    }
}
