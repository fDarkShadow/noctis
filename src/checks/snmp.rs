//! SNMP v2c probing via the `csnmp` crate.
//!
//! Probe a community string (or an explicit list) and GET one or more OIDs — the
//! common fingerprint path (sysDescr, default `public`/`private`, device/firmware
//! strings). The SNMP/BER wire format is handled by `csnmp`; this module only maps
//! it to/from the engine's feed-facing result.

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use csnmp::{ObjectIdentifier, ObjectValue, Snmp2cClient};
use serde::{Deserialize, Serialize};

use crate::error::{NoctisError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VarBind {
    pub oid: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpResult {
    pub responded: bool,
    pub community: Option<String>,
    pub version: String,
    pub varbinds: Vec<VarBind>,
    pub duration_ms: u64,
}

/// Render an SNMP value as a feed-matchable string.
fn render(value: &ObjectValue) -> String {
    match value {
        ObjectValue::Integer(i) => i.to_string(),
        ObjectValue::String(bytes) => {
            if bytes
                .iter()
                .all(|&b| b == 0x09 || b == 0x0a || b == 0x0d || (0x20..0x7f).contains(&b))
            {
                String::from_utf8_lossy(bytes).into_owned()
            } else {
                bytes.iter().map(|b| format!("{b:02x}")).collect()
            }
        }
        ObjectValue::ObjectId(oid) => oid.to_string(),
        ObjectValue::IpAddress(ip) => ip.to_string(),
        ObjectValue::Counter32(v) | ObjectValue::Unsigned32(v) | ObjectValue::TimeTicks(v) => {
            v.to_string()
        }
        ObjectValue::Counter64(v) => v.to_string(),
        ObjectValue::Opaque(bytes) => bytes.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

/// Probe each community in order; the first that returns values wins.
pub async fn get(
    host: &str,
    port: u16,
    communities: Vec<String>,
    oids: Vec<String>,
    timeout_secs: u64,
) -> Result<SnmpResult> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs.max(1));

    if oids.is_empty() {
        return Err(NoctisError::Snmp(
            "snmp_get requires at least one OID (set `oids:` in the step)".into(),
        ));
    }
    let oid_objs: Vec<ObjectIdentifier> = oids
        .iter()
        .map(|s| {
            ObjectIdentifier::from_str(s)
                .map_err(|e| NoctisError::Snmp(format!("bad OID {s}: {e}")))
        })
        .collect::<Result<_>>()?;

    let target: SocketAddr = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| NoctisError::Snmp(format!("resolve {host}:{port}: {e}")))?
        .next()
        .ok_or_else(|| NoctisError::Snmp(format!("no address for {host}:{port}")))?;

    let mut out = SnmpResult {
        responded: false,
        community: None,
        version: "v2c".to_string(),
        varbinds: Vec::new(),
        duration_ms: 0,
    };

    for community in &communities {
        let client = match Snmp2cClient::new(
            target,
            community.as_bytes().to_vec(),
            None,
            Some(timeout),
            0,
        )
        .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!("snmp client init failed: {e:?}");
                continue;
            }
        };
        match client.get_multiple(oid_objs.clone()).await {
            Ok(map) => {
                out.responded = true;
                out.community = Some(community.clone());
                out.varbinds = map
                    .iter()
                    .map(|(oid, val)| VarBind {
                        oid: oid.to_string(),
                        value: render(val),
                    })
                    .collect();
                break;
            }
            Err(_) => continue, // no reply / SNMP error → try next community
        }
    }

    out.duration_ms = start.elapsed().as_millis() as u64;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_printable_string() {
        assert_eq!(
            render(&ObjectValue::String(b"RouterOS".to_vec())),
            "RouterOS"
        );
    }

    #[test]
    fn renders_binary_string_as_hex() {
        assert_eq!(render(&ObjectValue::String(vec![0x00, 0xff])), "00ff");
    }

    #[test]
    fn renders_numbers() {
        assert_eq!(render(&ObjectValue::Integer(127)), "127");
        assert_eq!(render(&ObjectValue::Counter32(256)), "256");
        assert_eq!(render(&ObjectValue::TimeTicks(42)), "42");
    }

    #[test]
    fn parses_dotted_oid() {
        // sysDescr.0 (MIB-II) — the kind of OID a feed supplies in `oids:`.
        assert!(ObjectIdentifier::from_str("1.3.6.1.2.1.1.1.0").is_ok());
        assert!(ObjectIdentifier::from_str("not.an.oid").is_err());
    }

    #[tokio::test]
    async fn empty_oids_is_an_error() {
        let err = get("127.0.0.1", 161, vec!["public".into()], vec![], 1)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("OID"));
    }
}
