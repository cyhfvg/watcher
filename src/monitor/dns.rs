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

/// 解析全部已配置域名并记录 DNS 变化.
///
/// # 参数
///
/// - `db`: 域名资产和告警的数据库句柄.
/// - `config`: 读取自定义 DNS 服务器列表.
/// - `batch`: 当前监测批次.
///
/// # 返回
///
/// 全部域名处理完成或批次被要求停止时返回 `Ok(())`.
///
/// # Errors
///
/// 构造解析器, 列出域名, 写解析结果或写告警失败时返回错误. 单个域名解析失败只记日志和告警.
///
/// # 示例
///
/// ```no_run
/// # use watcher::{config::AppConfig, db::Database, models::BatchContext, monitor::dns};
/// # async fn demo(db: &Database, config: &AppConfig, batch: &BatchContext) -> anyhow::Result<()> {
/// dns::run(db, config, batch).await?;
/// # Ok(())
/// # }
/// ```
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
    /// 按配置创建解析器; 空服务器列表表示使用系统 DNS.
    ///
    /// # 参数
    ///
    /// - `servers`: `IP` 或 `IP:port` 形式的上游列表.
    ///
    /// # 返回
    ///
    /// [`DomainResolver::System`] 或自定义 hickory 解析器.
    ///
    /// # Errors
    ///
    /// 服务器地址无法解析, 或构造 hickory resolver 失败时返回错误.
    ///
    /// # 示例
    ///
    /// ```text
    /// let resolver = DomainResolver::new(&config.probe.dns_servers)?;
    /// ```
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

    /// 把域名解析为去重排序后的 IP 字符串列表.
    ///
    /// # 参数
    ///
    /// - `domain`: 待解析域名.
    ///
    /// # 返回
    ///
    /// 去重后的 IP 文本列表.
    ///
    /// # Errors
    ///
    /// 系统 `lookup_host` 或自定义 resolver 查询失败时返回错误.
    ///
    /// # 示例
    ///
    /// ```text
    /// let ips = resolver.resolve(&domain.name).await?;
    /// ```
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

/// 解析配置中的 DNS 服务器, 支持 `IP` 和 `IP:port`.
///
/// # 参数
///
/// - `value`: 服务器配置文本.
///
/// # 返回
///
/// 带 UDP/TCP 连接配置的 [`NameServerConfig`], 缺省端口为 53.
///
/// # Errors
///
/// 空字符串或既不是 IP 也不是 socket 地址时返回错误.
///
/// # 示例
///
/// ```text
/// let server = parse_name_server("8.8.8.8")?;
/// ```
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
