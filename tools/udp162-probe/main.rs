//! Standalone, dependency-free diagnostic; deliberately excluded from the product.
use std::{env, fs, io, net::UdpSocket, path::Path, process, time::Duration};

fn run() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 || !matches!(args[1].as_str(), "once" | "serve") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: udp162-probe once|serve IPv4:port STATE_FILE",
        ));
    }
    let state = Path::new(&args[3]);
    println!("pid={} mode={} address={}", process::id(), args[1], args[2]);
    let status = fs::read_to_string("/proc/self/status")?;
    for line in status.lines().filter(|s| {
        [
            "Uid:",
            "Gid:",
            "CapInh:",
            "CapPrm:",
            "CapEff:",
            "CapBnd:",
            "CapAmb:",
            "NoNewPrivs:",
        ]
        .iter()
        .any(|p| s.starts_with(p))
    }) {
        println!("{line}");
    }
    let effective_uid = status
        .lines()
        .find_map(|s| s.strip_prefix("Uid:"))
        .and_then(|s| s.split_whitespace().nth(1))
        .unwrap_or("unknown");
    if effective_uid == "0" {
        fs::write(state, "INVALID_ROOT\n")?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "probe must run as package user; root would invalidate the experiment",
        ));
    }
    let effective = status
        .lines()
        .find_map(|s| s.strip_prefix("CapEff:"))
        .and_then(|s| u64::from_str_radix(s.trim(), 16).ok());
    println!(
        "CAP_NET_BIND_SERVICE_effective={:?}",
        effective.map(|v| v & (1 << 10) != 0)
    );
    println!(
        "ip_unprivileged_port_start={}",
        fs::read_to_string("/proc/sys/net/ipv4/ip_unprivileged_port_start")
            .unwrap_or_else(|_| "unavailable".into())
            .trim()
    );
    match UdpSocket::bind(&args[2]) {
        Err(error) => {
            println!(
                "BIND_FAILED kind={:?} errno={:?} error={error}",
                error.kind(),
                error.raw_os_error()
            );
            fs::write(
                state,
                format!(
                    "BIND_FAILED kind={:?} errno={:?}\n",
                    error.kind(),
                    error.raw_os_error()
                ),
            )?;
            Err(error)
        }
        Ok(socket) => {
            println!("BIND_OK address={}", socket.local_addr()?);
            if args[1] == "once" {
                fs::write(state, "BIND_OK\n")?;
                return Ok(());
            }
            socket.set_read_timeout(Some(Duration::from_secs(1)))?;
            fs::write(state, "LISTENING received=0\n")?;
            let mut buffer = [0u8; 65535];
            let mut received: u64 = 0;
            loop {
                match socket.recv_from(&mut buffer) {
                    Ok((bytes, _peer)) => {
                        received = received.saturating_add(1);
                        // Fixed-size state: no payloads, peer addresses, or growing packet log.
                        let pending = state.with_extension("tmp");
                        fs::write(
                            &pending,
                            format!("LISTENING received={received} last_bytes={bytes}\n"),
                        )?;
                        fs::rename(pending, state)?;
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) => return Err(e),
                }
            }
        }
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("probe error: {error}");
        process::exit(1);
    }
}
