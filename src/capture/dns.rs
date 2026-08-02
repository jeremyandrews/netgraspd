//! A read-only DNS message walker, sized for mDNS.
//!
//! This is hand-rolled rather than delegated to a DNS library for two reasons.
//!
//! 1. **Passivity.** Every mDNS service-discovery crate discovers by asking, and
//!    even joining the multicast group emits an IGMP membership report. Netgrasp
//!    reads frames that pcap hands it and transmits nothing, so it needs a
//!    parser, not a client.
//! 2. **The cache-flush bit.** Real mDNS responders set the top bit of the class
//!    field on records they consider authoritative, so a class arrives as
//!    `0x8001` rather than `0x0001`. A general-purpose DNS parser is entitled to
//!    treat that as an unknown class; here it is masked off deliberately.
//!
//! The walker never allocates for records it does not yield, never follows a
//! compression pointer forwards, and bounds pointer chains, so a malicious
//! packet cannot loop it.

/// Maximum compression pointers followed while reading one name. A legitimate
/// name needs at most a handful; a chain longer than this is an attack.
const MAX_POINTERS: usize = 16;

/// Maximum labels in one name, per RFC 1035's 255-octet name limit.
const MAX_LABELS: usize = 64;

/// Record type for a host address.
pub const TYPE_A: u16 = 1;
/// Record type for a domain name pointer.
pub const TYPE_PTR: u16 = 12;
/// Record type for descriptive text.
pub const TYPE_TXT: u16 = 16;
/// Record type for an IPv6 host address.
pub const TYPE_AAAA: u16 = 28;
/// Record type for a service location.
pub const TYPE_SRV: u16 = 33;

/// A parsed resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record<'a> {
    /// The record's owner name, split into labels with escaping already
    /// resolved. mDNS instance names legitimately contain spaces and dots, and
    /// keeping labels separate is what avoids having to unescape them later.
    pub name: Vec<String>,
    /// Record type.
    pub rtype: u16,
    /// Class with the mDNS cache-flush bit masked off.
    pub class: u16,
    /// True when the responder set the cache-flush bit.
    pub cache_flush: bool,
    /// Time to live, seconds. A TTL of zero is a goodbye announcement.
    pub ttl: u32,
    /// Raw record data, still in the message buffer so that names inside it can
    /// resolve their compression pointers.
    pub rdata: &'a [u8],
}

/// A parsed DNS message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    /// True when this is a response (the QR bit).
    pub is_response: bool,
    /// True when the responder claims authority (the AA bit), which every mDNS
    /// announcement does.
    pub authoritative: bool,
    /// Question names, kept because a probe announces the name it is claiming.
    pub questions: Vec<Vec<String>>,
    /// Answer, authority and additional records, concatenated. mDNS responders
    /// scatter useful records across all three sections and the distinction
    /// carries no information Netgrasp needs.
    pub records: Vec<Record<'a>>,
}

/// Parses a DNS message.
///
/// Returns `None` when the header is truncated or a section is unreadable. A
/// message whose record count runs past the buffer yields the records that were
/// complete rather than failing outright, because a snaplen-truncated capture is
/// normal and its first records are still good.
#[must_use]
pub fn parse_message(buf: &[u8]) -> Option<Message<'_>> {
    if buf.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let counts = [
        u16::from_be_bytes([buf[6], buf[7]]),   // answers
        u16::from_be_bytes([buf[8], buf[9]]),   // authority
        u16::from_be_bytes([buf[10], buf[11]]), // additional
    ];

    let mut offset = 12;
    let mut questions = Vec::new();
    for _ in 0..qdcount {
        let (name, next) = read_name(buf, offset)?;
        // Question type and class.
        offset = next.checked_add(4)?;
        if offset > buf.len() {
            return None;
        }
        questions.push(name);
    }

    let total: usize = counts.iter().map(|c| usize::from(*c)).sum();
    let mut records = Vec::with_capacity(total.min(256));
    for _ in 0..total {
        match read_record(buf, offset) {
            Some((record, next)) => {
                records.push(record);
                offset = next;
            }
            // Truncated tail: keep what parsed cleanly.
            None => break,
        }
    }

    Some(Message {
        is_response: flags & 0x8000 != 0,
        authoritative: flags & 0x0400 != 0,
        questions,
        records,
    })
}

/// Reads one resource record, returning it and the offset just past it.
fn read_record(buf: &[u8], offset: usize) -> Option<(Record<'_>, usize)> {
    let (name, after_name) = read_name(buf, offset)?;
    let rtype = read_u16(buf, after_name)?;
    let raw_class = read_u16(buf, after_name + 2)?;
    let ttl = u32::from_be_bytes([
        *buf.get(after_name + 4)?,
        *buf.get(after_name + 5)?,
        *buf.get(after_name + 6)?,
        *buf.get(after_name + 7)?,
    ]);
    let rdlength = usize::from(read_u16(buf, after_name + 8)?);
    let rdata_start = after_name + 10;
    let rdata_end = rdata_start.checked_add(rdlength)?;
    let rdata = buf.get(rdata_start..rdata_end)?;
    Some((
        Record {
            name,
            rtype,
            class: raw_class & 0x7fff,
            cache_flush: raw_class & 0x8000 != 0,
            ttl,
            rdata,
        },
        rdata_end,
    ))
}

/// Reads a possibly compressed name, returning its labels and the offset just
/// past the name **in the original position**, which is what the caller needs to
/// keep walking.
///
/// Labels are returned as lossy UTF-8. mDNS instance names are UTF-8 by
/// specification and a responder that emits anything else has already lost the
/// argument about what its name is.
#[must_use]
pub fn read_name(buf: &[u8], start: usize) -> Option<(Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut end_of_name: Option<usize> = None;
    let mut pointers = 0usize;

    loop {
        let len = *buf.get(offset)?;
        match len & 0xc0 {
            0 => {
                if len == 0 {
                    let end = end_of_name.unwrap_or(offset + 1);
                    return Some((labels, end));
                }
                let from = offset + 1;
                let to = from.checked_add(usize::from(len))?;
                let label = buf.get(from..to)?;
                labels.push(String::from_utf8_lossy(label).into_owned());
                if labels.len() > MAX_LABELS {
                    return None;
                }
                offset = to;
            }
            0xc0 => {
                let lo = *buf.get(offset + 1)?;
                let target = usize::from(u16::from_be_bytes([len & 0x3f, lo]));
                // A pointer must go backwards; forwards or self-referential
                // pointers are the classic decompression-bomb shape.
                if target >= offset {
                    return None;
                }
                pointers += 1;
                if pointers > MAX_POINTERS {
                    return None;
                }
                end_of_name.get_or_insert(offset + 2);
                offset = target;
            }
            // 0x40 and 0x80 are reserved label types; nothing legitimate emits
            // them and guessing at their length is how parsers desynchronise.
            _ => return None,
        }
    }
}

/// Reads a big-endian `u16`.
fn read_u16(buf: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *buf.get(offset)?,
        *buf.get(offset + 1)?,
    ]))
}

/// Reads the target name out of a PTR record's rdata.
#[must_use]
pub fn ptr_target(msg: &[u8], record: &Record<'_>) -> Option<Vec<String>> {
    let offset = rdata_offset(msg, record.rdata)?;
    read_name(msg, offset).map(|(labels, _)| labels)
}

/// Reads the target name out of an SRV record's rdata, skipping priority,
/// weight and port.
#[must_use]
pub fn srv_target(msg: &[u8], record: &Record<'_>) -> Option<Vec<String>> {
    let offset = rdata_offset(msg, record.rdata)?.checked_add(6)?;
    read_name(msg, offset).map(|(labels, _)| labels)
}

/// Splits a TXT record into its length-prefixed strings.
#[must_use]
pub fn txt_strings(record: &Record<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < record.rdata.len() {
        let len = usize::from(record.rdata[i]);
        i += 1;
        let Some(chunk) = record.rdata.get(i..i + len) else {
            break;
        };
        out.push(String::from_utf8_lossy(chunk).into_owned());
        i += len;
    }
    out
}

/// Offset of a record's rdata within the whole message.
///
/// The rdata slice is borrowed from the message buffer, so its position is the
/// difference between the two pointers. That is what lets names inside rdata
/// resolve compression pointers back into the message.
fn rdata_offset(msg: &[u8], rdata: &[u8]) -> Option<usize> {
    let base = msg.as_ptr() as usize;
    let here = rdata.as_ptr() as usize;
    let offset = here.checked_sub(base)?;
    (offset <= msg.len()).then_some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds `len`-prefixed labels followed by a root byte.
    fn name(labels: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for l in labels {
            out.push(u8::try_from(l.len()).expect("test label fits"));
            out.extend_from_slice(l.as_bytes());
        }
        out.push(0);
        out
    }

    fn header(flags: u16, qd: u16, an: u16) -> Vec<u8> {
        let mut h = vec![0, 0];
        h.extend_from_slice(&flags.to_be_bytes());
        h.extend_from_slice(&qd.to_be_bytes());
        h.extend_from_slice(&an.to_be_bytes());
        h.extend_from_slice(&0u16.to_be_bytes());
        h.extend_from_slice(&0u16.to_be_bytes());
        h
    }

    #[test]
    fn parses_an_a_record_with_the_cache_flush_bit_set() {
        let mut m = header(0x8400, 0, 1);
        m.extend_from_slice(&name(&["printer", "local"]));
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&0x8001u16.to_be_bytes()); // flush + IN
        m.extend_from_slice(&120u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[192, 168, 1, 55]);

        let msg = parse_message(&m).expect("parsed");
        assert!(msg.is_response);
        assert!(msg.authoritative);
        assert_eq!(msg.records.len(), 1);
        let r = &msg.records[0];
        assert_eq!(r.name, vec!["printer", "local"]);
        assert_eq!(r.class, 1, "the flush bit must be masked off, not rejected");
        assert!(r.cache_flush);
        assert_eq!(r.rdata, &[192, 168, 1, 55]);
    }

    #[test]
    fn resolves_a_compression_pointer_in_ptr_rdata() {
        // The service name appears once and the PTR target points back at it.
        let mut m = header(0x8400, 0, 1);
        let service_at = m.len();
        m.extend_from_slice(&name(&["_airplay", "_tcp", "local"]));
        m.extend_from_slice(&TYPE_PTR.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&4500u32.to_be_bytes());

        let mut rdata = Vec::new();
        rdata.push(u8::try_from("Living Room Apple TV".len()).expect("fits"));
        rdata.extend_from_slice(b"Living Room Apple TV");
        rdata.extend_from_slice(&[0xc0, u8::try_from(service_at).expect("offset fits")]);
        m.extend_from_slice(&u16::try_from(rdata.len()).expect("fits").to_be_bytes());
        m.extend_from_slice(&rdata);

        let msg = parse_message(&m).expect("parsed");
        let target = ptr_target(&m, &msg.records[0]).expect("target");
        assert_eq!(
            target,
            vec!["Living Room Apple TV", "_airplay", "_tcp", "local"]
        );
    }

    #[test]
    fn reads_an_srv_target_past_the_fixed_fields() {
        let mut m = header(0x8400, 0, 1);
        m.extend_from_slice(&name(&["Office Printer", "_ipp", "_tcp", "local"]));
        m.extend_from_slice(&TYPE_SRV.to_be_bytes());
        m.extend_from_slice(&0x8001u16.to_be_bytes());
        m.extend_from_slice(&120u32.to_be_bytes());
        let mut rdata = vec![0, 0, 0, 0, 0x02, 0x77]; // priority, weight, port 631
        rdata.extend_from_slice(&name(&["printer", "local"]));
        m.extend_from_slice(&u16::try_from(rdata.len()).expect("fits").to_be_bytes());
        m.extend_from_slice(&rdata);

        let msg = parse_message(&m).expect("parsed");
        let target = srv_target(&m, &msg.records[0]).expect("target");
        assert_eq!(target, vec!["printer", "local"]);
    }

    #[test]
    fn splits_txt_strings() {
        let mut m = header(0x8400, 0, 1);
        m.extend_from_slice(&name(&["Office Printer", "_ipp", "_tcp", "local"]));
        m.extend_from_slice(&TYPE_TXT.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&120u32.to_be_bytes());
        let mut rdata = Vec::new();
        for s in ["ty=Brother HL-L2350DW", "product=(Brother)"] {
            rdata.push(u8::try_from(s.len()).expect("fits"));
            rdata.extend_from_slice(s.as_bytes());
        }
        m.extend_from_slice(&u16::try_from(rdata.len()).expect("fits").to_be_bytes());
        m.extend_from_slice(&rdata);

        let msg = parse_message(&m).expect("parsed");
        assert_eq!(
            txt_strings(&msg.records[0]),
            vec!["ty=Brother HL-L2350DW", "product=(Brother)"]
        );
    }

    #[test]
    fn questions_are_walked_before_the_answers() {
        let mut m = header(0x0000, 1, 1);
        m.extend_from_slice(&name(&["_services", "_dns-sd", "_udp", "local"]));
        m.extend_from_slice(&TYPE_PTR.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&name(&["thermostat", "local"]));
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&120u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[10, 0, 0, 9]);

        let msg = parse_message(&m).expect("parsed");
        assert!(!msg.is_response);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0][0], "_services");
        assert_eq!(msg.records.len(), 1);
        assert_eq!(msg.records[0].name, vec!["thermostat", "local"]);
    }

    #[test]
    fn a_forward_pointer_is_refused() {
        let mut m = header(0x8400, 0, 1);
        let here = m.len();
        // Points at itself, which is both forwards and a loop.
        m.extend_from_slice(&[0xc0, u8::try_from(here).expect("fits")]);
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&120u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[1, 2, 3, 4]);
        let msg = parse_message(&m).expect("header still parses");
        assert!(msg.records.is_empty(), "the bad record must be dropped");
    }

    #[test]
    fn a_backwards_pointer_loop_is_bounded() {
        // Two pointers aiming at each other: the second is backwards from the
        // first, so only the pointer budget stops it.
        let mut m = header(0x8400, 0, 1);
        let a = m.len();
        m.extend_from_slice(&[0xc0, u8::try_from(a + 2).expect("fits")]);
        m.extend_from_slice(&[0xc0, u8::try_from(a).expect("fits")]);
        // The forward half is refused outright, so this must not hang.
        assert!(read_name(&m, a).is_none());
    }

    #[test]
    fn reserved_label_types_are_refused() {
        let mut m = header(0x8400, 0, 1);
        m.push(0x40); // reserved label type
        m.extend_from_slice(&[0u8; 16]);
        let msg = parse_message(&m).expect("header parses");
        assert!(msg.records.is_empty());
    }

    #[test]
    fn a_truncated_tail_keeps_the_records_that_parsed() {
        let mut m = header(0x8400, 0, 3); // claims three, carries one
        m.extend_from_slice(&name(&["nas", "local"]));
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&120u32.to_be_bytes());
        m.extend_from_slice(&4u16.to_be_bytes());
        m.extend_from_slice(&[10, 0, 0, 5]);
        let msg = parse_message(&m).expect("parsed");
        assert_eq!(msg.records.len(), 1);
    }

    #[test]
    fn short_buffers_return_none_without_panicking() {
        for n in 0..12 {
            assert!(parse_message(&vec![0u8; n]).is_none(), "len {n}");
        }
    }

    #[test]
    fn an_rdlength_past_the_buffer_is_refused() {
        let mut m = header(0x8400, 0, 1);
        m.extend_from_slice(&name(&["x", "local"]));
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(&120u32.to_be_bytes());
        m.extend_from_slice(&9999u16.to_be_bytes());
        m.extend_from_slice(&[1, 2, 3, 4]);
        let msg = parse_message(&m).expect("header parses");
        assert!(msg.records.is_empty());
    }
}
