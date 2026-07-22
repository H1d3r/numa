#![no_main]
//! A packet the parser accepts must survive a write→re-parse cycle. Catches
//! serializer bugs (bad compression pointers, length fields that disagree with
//! the parser) where numa would emit a reply that nothing — including numa —
//! can read back.
use libfuzzer_sys::fuzz_target;
use numa::buffer::BytePacketBuffer;
use numa::packet::DnsPacket;

fuzz_target!(|data: &[u8]| {
    let mut buf = BytePacketBuffer::from_bytes(data);
    let Ok(packet) = DnsPacket::from_buffer(&mut buf) else {
        return; // unparseable input is the parser's job, not the serializer's
    };

    let mut out = BytePacketBuffer::new();
    if packet.write(&mut out).is_err() {
        return; // legitimate: oversized records can exceed the 512-byte buffer
    }

    let written = out.filled().to_vec();
    let mut reparse = BytePacketBuffer::from_bytes(&written);
    let reparsed =
        DnsPacket::from_buffer(&mut reparse).expect("numa serialized a packet it cannot parse");

    assert_eq!(
        reparsed.questions.len(),
        packet.questions.len(),
        "question count changed across round-trip"
    );
});
