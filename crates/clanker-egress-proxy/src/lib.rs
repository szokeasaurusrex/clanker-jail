pub mod policy;

use std::future::Future;
use std::io::{Write, stdout};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::{Context, Result, anyhow};
use fast_socks5::server::{Socks5ServerProtocol, transfer};
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::task;

/// Runs the filtered SOCKS5 egress proxy until its supervisor pipe closes.
///
/// # Errors
///
/// Returns an error when the listener cannot be created, startup output cannot
/// be flushed, or accepting client connections fails.
pub async fn run() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("failed to bind egress proxy listener")?;
    let addr = listener
        .local_addr()
        .context("failed to read egress proxy listener address")?;

    println!("CLANKER_EGRESS_PROXY={addr}");
    stdout()
        .flush()
        .context("failed to flush egress proxy startup line")?;
    eprintln!("clanker-egress-proxy listening on {addr}");
    std::thread::spawn(|| {
        let mut buffer = String::new();
        let _ = std::io::stdin().read_line(&mut buffer);
        eprintln!("clanker-egress-proxy supervisor pipe closed; exiting");
        std::process::exit(0);
    });

    loop {
        let (socket, client_addr) = listener
            .accept()
            .await
            .context("failed to accept SOCKS5 connection")?;
        spawn_and_log_error(async move {
            serve_socks5(socket)
                .await
                .with_context(|| format!("SOCKS5 client {client_addr}"))
        });
    }
}

async fn serve_socks5(socket: TcpStream) -> Result<()> {
    let (proto, command, target_addr) = Socks5ServerProtocol::accept_no_auth(socket)
        .await
        .map_err(|err| anyhow!(err))?
        .read_command()
        .await
        .map_err(|err| anyhow!(err))?;

    if command != Socks5Command::TCPConnect {
        proto
            .reply_error(&ReplyError::CommandNotSupported)
            .await
            .map_err(|err| anyhow!(err))?;
        return Ok(());
    }

    let destination = target_addr.to_string();
    let upstream_addr = match resolve_allowed(target_addr).await {
        Ok(addr) => addr,
        Err(err) => {
            eprintln!("denied SOCKS5 request to {destination}: {err:#}");
            proto
                .reply_error(&ReplyError::ConnectionNotAllowed)
                .await
                .map_err(|err| anyhow!(err))?;
            return Ok(());
        }
    };

    let upstream = match TcpStream::connect(upstream_addr).await {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("failed SOCKS5 upstream connect to {upstream_addr}: {err}");
            proto
                .reply_error(&ReplyError::HostUnreachable)
                .await
                .map_err(|err| anyhow!(err))?;
            return Ok(());
        }
    };

    let local_addr = upstream
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let inner = proto
        .reply_success(local_addr)
        .await
        .map_err(|err| anyhow!(err))?;
    transfer(inner, upstream).await;
    Ok(())
}

async fn resolve_allowed(target_addr: TargetAddr) -> Result<SocketAddr> {
    match target_addr {
        TargetAddr::Ip(addr) => {
            policy::validate_socket_addr(addr)?;
            Ok(addr)
        }
        TargetAddr::Domain(domain, port) => {
            let mut blocked = Vec::new();
            for addr in lookup_host((domain.as_str(), port))
                .await
                .with_context(|| format!("failed to resolve {domain}:{port}"))?
            {
                if policy::is_blocked_ip(addr.ip()) {
                    blocked.push(addr);
                } else {
                    return Ok(addr);
                }
            }
            if blocked.is_empty() {
                Err(anyhow!("DNS returned no records for {domain}:{port}"))
            } else {
                Err(anyhow!(
                    "DNS returned only blocked addresses for {domain}:{port}: {blocked:?}"
                ))
            }
        }
    }
}

fn spawn_and_log_error<F>(future: F) -> task::JoinHandle<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    task::spawn(async move {
        if let Err(err) = future.await {
            eprintln!("{err:#}");
        }
    })
}
