//! Raw TCP SYN probe via `pnet` — half-open connect to classify a port as
//! open / closed / filtered from the peer's response (SYN-ACK / RST / none).
//!
//! Requires raw-socket privileges (CAP_NET_RAW or root) at runtime. When the
//! platform denies the raw socket the probe returns `state = "unprivileged"`
//! rather than failing the scan.
//!
//! IPv4 only. The TCP checksum needs the source address the kernel will route
//! from, which we learn with a connected (no packets sent) UDP socket.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{tcp_packet_iter, transport_channel};
use serde::{Deserialize, Serialize};

use crate::error::{NoctisError, Result};

const TCP_HEADER_LEN: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynResult {
    /// "open" | "closed" | "filtered" | "unprivileged" | "error"
    pub state: String,
    /// TCP flags of the reply, when one arrived (e.g. "SYN,ACK").
    pub flags: Option<String>,
    pub src_port: u16,
    pub duration_ms: u64,
}

/// Source IPv4 the kernel would use to reach `dst` (no packets are sent).
fn local_src_ip(dst: Ipv4Addr, dst_port: u16) -> Result<Ipv4Addr> {
    let sock =
        UdpSocket::bind("0.0.0.0:0").map_err(|e| NoctisError::Tcp(format!("udp bind: {e}")))?;
    sock.connect((dst, dst_port))
        .map_err(|e| NoctisError::Tcp(format!("udp connect: {e}")))?;
    match sock
        .local_addr()
        .map_err(|e| NoctisError::Tcp(format!("local_addr: {e}")))?
        .ip()
    {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(NoctisError::Tcp("syn probe is IPv4-only".into())),
    }
}

/// Build a SYN segment into `buf` (must be >= 20 bytes) and set its checksum.
fn build_syn(
    buf: &mut [u8],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
) -> Option<()> {
    let mut pkt = MutableTcpPacket::new(buf)?;
    pkt.set_source(src_port);
    pkt.set_destination(dst_port);
    pkt.set_sequence(0x1234_5678);
    pkt.set_acknowledgement(0);
    pkt.set_data_offset(5); // 5 * 4 = 20 bytes, no options
    pkt.set_flags(TcpFlags::SYN);
    pkt.set_window(64240);
    pkt.set_urgent_ptr(0);
    pkt.set_checksum(0);
    let checksum = tcp::ipv4_checksum(&pkt.to_immutable(), &src_ip, &dst_ip);
    pkt.set_checksum(checksum);
    Some(())
}

/// Classify a reply by its TCP flags.
fn classify(flags: u8) -> &'static str {
    if flags & TcpFlags::RST != 0 {
        "closed"
    } else if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
        "open"
    } else {
        "unknown"
    }
}

fn flags_label(flags: u8) -> String {
    let mut parts = Vec::new();
    for (bit, name) in [
        (TcpFlags::SYN, "SYN"),
        (TcpFlags::ACK, "ACK"),
        (TcpFlags::RST, "RST"),
        (TcpFlags::FIN, "FIN"),
        (TcpFlags::PSH, "PSH"),
        (TcpFlags::URG, "URG"),
    ] {
        if flags & bit != 0 {
            parts.push(name);
        }
    }
    parts.join(",")
}

/// Send a SYN and wait for the first matching reply, or time out (filtered).
pub async fn syn_probe(host: &str, port: u16, timeout_secs: u64) -> Result<SynResult> {
    let start = Instant::now();

    // Resolve to an IPv4 address.
    let dst_ip = {
        let mut found = None;
        for addr in tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| NoctisError::Tcp(format!("resolve {host}: {e}")))?
        {
            if let IpAddr::V4(v4) = addr.ip() {
                found = Some(v4);
                break;
            }
        }
        found.ok_or_else(|| NoctisError::Tcp(format!("no IPv4 address for {host}")))?
    };

    let src_ip = local_src_ip(dst_ip, port)?;
    let src_port: u16 = 40000 + (std::process::id() as u16 % 20000);
    let budget = Duration::from_secs(timeout_secs.max(1));

    // pnet is blocking: run the raw-socket work on a blocking thread.
    let res = tokio::task::spawn_blocking(move || -> SynResult {
        let (mut tx, mut rx) =
            match transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Tcp))) {
                Ok(c) => c,
                Err(e) => {
                    let state = if e.kind() == std::io::ErrorKind::PermissionDenied {
                        "unprivileged"
                    } else {
                        "error"
                    };
                    return SynResult {
                        state: state.into(),
                        flags: None,
                        src_port,
                        duration_ms: start.elapsed().as_millis() as u64,
                    };
                }
            };

        let mut buf = [0u8; TCP_HEADER_LEN];
        if build_syn(&mut buf, src_ip, dst_ip, src_port, port).is_none() {
            return SynResult {
                state: "error".into(),
                flags: None,
                src_port,
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }
        let syn = TcpPacket::new(&buf).unwrap();
        if tx.send_to(syn, IpAddr::V4(dst_ip)).is_err() {
            return SynResult {
                state: "error".into(),
                flags: None,
                src_port,
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }

        let mut iter = tcp_packet_iter(&mut rx);
        loop {
            let remaining = budget.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }
            match iter.next_with_timeout(remaining) {
                Ok(Some((reply, addr))) => {
                    if addr == IpAddr::V4(dst_ip)
                        && reply.get_source() == port
                        && reply.get_destination() == src_port
                    {
                        let flags = reply.get_flags();
                        return SynResult {
                            state: classify(flags).into(),
                            flags: Some(flags_label(flags)),
                            src_port,
                            duration_ms: start.elapsed().as_millis() as u64,
                        };
                    }
                }
                Ok(None) => continue,
                Err(_) => break,
            }
        }
        SynResult {
            state: "filtered".into(),
            flags: None,
            src_port,
            duration_ms: start.elapsed().as_millis() as u64,
        }
    })
    .await
    .map_err(|e| NoctisError::Tcp(format!("syn probe thread: {e}")))?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_syn_segment() {
        let mut buf = [0u8; TCP_HEADER_LEN];
        build_syn(
            &mut buf,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            40001,
            80,
        )
        .unwrap();
        let pkt = TcpPacket::new(&buf).unwrap();
        assert_eq!(pkt.get_source(), 40001);
        assert_eq!(pkt.get_destination(), 80);
        assert_eq!(pkt.get_flags() & TcpFlags::SYN, TcpFlags::SYN);
        assert_eq!(pkt.get_data_offset(), 5);
        assert_ne!(pkt.get_checksum(), 0);
    }

    #[test]
    fn classifies_replies() {
        assert_eq!(classify(TcpFlags::SYN | TcpFlags::ACK), "open");
        assert_eq!(classify(TcpFlags::RST | TcpFlags::ACK), "closed");
        assert_eq!(classify(TcpFlags::ACK), "unknown");
    }

    #[test]
    fn flag_label_formats() {
        assert_eq!(flags_label(TcpFlags::SYN | TcpFlags::ACK), "SYN,ACK");
        assert_eq!(flags_label(TcpFlags::RST), "RST");
    }

    #[test]
    fn src_ip_for_loopback_is_v4() {
        // UDP-connect to loopback sends nothing but resolves the local source IP.
        let ip = local_src_ip(Ipv4Addr::new(127, 0, 0, 1), 80).unwrap();
        assert!(ip.is_loopback() || !ip.is_unspecified());
    }
}
