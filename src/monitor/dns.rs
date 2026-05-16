//! DNS resolution monitoring.

use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
};

use hickory_resolver::{
    Resolver,
    config::{ConnectionConfig, NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use tokio::net::lookup_host;
use tracing::warn;

use crate::{config::AppConfig, db::Database, models::BatchContext};

/// Resolves all configured domain names and records DNS changes.
pub async fn run(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
    let resolver = DomainResolver::new(&config.probe.dns_servers)?;
    for domain in db.list_domains()? {
        if db.should_stop_batch(&batch.id)? {
            break;
        }
        match resolver.resolve(&domain.name).await {
            Ok(ips) if !ips.is_empty() => db.update_domain_resolution(&batch.id, &domain, &ips)?,
            Ok(_) => warn!(domain = %domain.name, "domain resolved to no addresses"),
            Err(error) => {
                warn!(domain = %domain.name, %error, "domain resolution failed");
                db.add_alert(
                    &batch.id,
                    Some(&domain.system_id),
                    "dns_error",
                    "low",
                    &domain.name,
                    None,
                    None,
                    Some(&error.to_string()),
                )?;
            }
        }
    }
    Ok(())
}

/// DNS resolver backend selected from configuration.
enum DomainResolver {
    /// Use host/system DNS configuration.
    System,
    /// Use configured upstream DNS servers.
    Custom(Box<Resolver<TokioRuntimeProvider>>),
}

impl DomainResolver {
    /// Creates a resolver. Empty server list means system DNS.
    fn new(servers: &[String]) -> anyhow::Result<Self> {
        if servers.is_empty() {
            return Ok(Self::System);
        }
        let name_servers = servers
            .iter()
            .map(|server| parse_name_server(server))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let config = ResolverConfig::from_parts(None, vec![], name_servers);
        let resolver =
            Resolver::builder_with_config(config, TokioRuntimeProvider::default()).build()?;
        Ok(Self::Custom(Box::new(resolver)))
    }

    /// Resolves a domain to sorted unique IP address strings.
    async fn resolve(&self, domain: &str) -> anyhow::Result<Vec<String>> {
        let ips = match self {
            Self::System => {
                let addrs = lookup_host((domain, 0)).await?;
                addrs.map(|addr| addr.ip()).collect::<BTreeSet<_>>()
            }
            Self::Custom(resolver) => resolver.lookup_ip(domain).await?.iter().collect(),
        };
        Ok(ips.into_iter().map(|ip| ip.to_string()).collect())
    }
}

/// Parses a configured DNS server. Supports `IP` and `IP:port` forms.
fn parse_name_server(value: &str) -> anyhow::Result<NameServerConfig> {
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "dns server must not be empty");
    let (ip, port) = match value.parse::<IpAddr>() {
        Ok(ip) => (ip, 53),
        Err(_) => {
            let socket = value
                .parse::<SocketAddr>()
                .map_err(|_| anyhow::anyhow!("invalid dns server `{value}`; use IP or IP:port"))?;
            (socket.ip(), socket.port())
        }
    };
    let mut udp = ConnectionConfig::udp();
    udp.port = port;
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = port;
    Ok(NameServerConfig::new(ip, true, vec![udp, tcp]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_server_ip_with_default_port() {
        let server = parse_name_server("8.8.8.8").unwrap();
        assert_eq!(server.ip.to_string(), "8.8.8.8");
        assert_eq!(server.connections[0].port, 53);
    }

    #[test]
    fn parses_dns_server_socket_addr() {
        let server = parse_name_server("1.1.1.1:5353").unwrap();
        assert_eq!(server.ip.to_string(), "1.1.1.1");
        assert_eq!(server.connections[0].port, 5353);
    }
}
