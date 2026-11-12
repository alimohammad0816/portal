//! Just enough DNS wire format to read a query's name and the A/AAAA
//! records of an answer. Messages are forwarded byte for byte; this only
//! looks at them.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

/// Read a (possibly compressed) name at `pos`. Returns the name and the
/// position right after it in the original message.
fn read_name(b: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *b.get(pos)? as usize;
        if len == 0 {
            end.get_or_insert(pos + 1);
            break;
        }
        if len & 0xC0 == 0xC0 {
            let ptr = (u16_at(b, pos)? & 0x3FFF) as usize;
            end.get_or_insert(pos + 2);
            jumps += 1;
            if jumps > 16 || ptr >= b.len() {
                return None;
            }
            pos = ptr;
            continue;
        }
        if len > 63 {
            return None;
        }
        let label = b.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
        if labels.len() > 127 {
            return None;
        }
    }
    Some((labels.join("."), end?))
}

/// Name asked about in the first question.
pub fn question_name(msg: &[u8]) -> Option<String> {
    if u16_at(msg, 4)? == 0 {
        return None;
    }
    read_name(msg, 12).map(|(n, _)| n)
}

/// A and AAAA records in the answer section, with their TTLs.
pub fn answer_addresses(msg: &[u8]) -> Vec<(IpAddr, u32)> {
    let mut out = Vec::new();
    let _ = (|| -> Option<()> {
        let qd = u16_at(msg, 4)?;
        let an = u16_at(msg, 6)?;
        let mut pos = 12;
        for _ in 0..qd {
            pos = read_name(msg, pos)?.1 + 4;
        }
        for _ in 0..an {
            pos = read_name(msg, pos)?.1;
            let ty = u16_at(msg, pos)?;
            let ttl = u32_at(msg, pos + 4)?;
            let len = u16_at(msg, pos + 8)? as usize;
            let data = msg.get(pos + 10..pos + 10 + len)?;
            match (ty, len) {
                (TYPE_A, 4) => out.push((
                    IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                    ttl,
                )),
                (TYPE_AAAA, 16) => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(data);
                    out.push((IpAddr::V6(Ipv6Addr::from(a)), ttl));
                }
                _ => {}
            }
            pos += 10 + len;
        }
        Some(())
    })();
    out
}

/// A SERVFAIL reply to `query`, sent when no upstream answers.
pub fn servfail(query: &[u8]) -> Option<Vec<u8>> {
    let mut r = query.get(..12)?.to_vec();
    r[2] = 0x80 | (query[2] & 0x01); // QR, keep RD
    r[3] = 0x80 | 0x02; // RA, SERVFAIL
    r[6..12].fill(0);
    // Keep the question section.
    let end = read_name(query, 12)?.1 + 4;
    r[4..6].copy_from_slice(&1u16.to_be_bytes());
    r.extend_from_slice(query.get(12..end)?);
    Some(r)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Build a query for `name` (type A).
    pub fn query(id: u16, name: &str) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        for l in name.split('.') {
            m.push(l.len() as u8);
            m.extend_from_slice(l.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        m
    }

    /// Answer `q` with a CNAME (compressed) and the given A records.
    pub fn answer(q: &[u8], addrs: &[[u8; 4]], ttl: u32) -> Vec<u8> {
        let mut m = q.to_vec();
        m[2] = 0x81;
        m[3] = 0x80;
        m[7] = (addrs.len() + 1) as u8;
        // CNAME pointing back at the question name
        m.extend_from_slice(&[0xC0, 12, 0, 5, 0, 1]);
        m.extend_from_slice(&ttl.to_be_bytes());
        m.extend_from_slice(&[0, 2, 0xC0, 12]);
        for a in addrs {
            m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&[0, 4]);
            m.extend_from_slice(a);
        }
        m
    }

    #[test]
    fn reads_questions_and_answers() {
        let q = query(7, "www.Digikala.com");
        assert_eq!(question_name(&q).as_deref(), Some("www.digikala.com"));
        let a = answer(&q, &[[1, 2, 3, 4], [5, 6, 7, 8]], 120);
        assert_eq!(
            answer_addresses(&a),
            vec![
                ("1.2.3.4".parse().unwrap(), 120),
                ("5.6.7.8".parse().unwrap(), 120)
            ]
        );
    }

    #[test]
    fn survives_garbage() {
        assert!(question_name(&[0; 5]).is_none());
        assert!(answer_addresses(&[0xff; 40]).is_empty());
        let mut loopy = query(1, "a.b");
        loopy[12] = 0xC0;
        loopy[13] = 12;
        assert!(question_name(&loopy).is_none());
    }

    #[test]
    fn builds_servfail() {
        let q = query(9, "x.ir");
        let r = servfail(&q).unwrap();
        assert_eq!(&r[..2], &9u16.to_be_bytes());
        assert_eq!(r[3] & 0x0f, 2);
        assert_eq!(question_name(&r).as_deref(), Some("x.ir"));
    }
}
