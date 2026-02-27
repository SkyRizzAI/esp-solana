//! NXP SE05x secure element driver for Ed25519 wallet operations.
//!
//! Communicates with the SE05x over I²C using the T=1 over I²C protocol
//! (ISO 7816-3) and APDU commands (ISO 7816-4). Keys are generated and
//! stored inside the secure element; signing is performed on-chip so
//! private key material never leaves the SE05x.
//!
//! # Example
//!
//! ```rust,ignore
//! use esp_solana::se05x::Se05xSigner;
//! use esp_solana::signer::Signer;
//! use esp_solana::transaction::Transaction;
//!
//! // `i2c` must implement `embedded_hal::i2c::I2c`.
//! let mut se = Se05xSigner::new(i2c, 0x0001_0001);
//! se.generate_ed25519()?;
//!
//! let pubkey = se.pubkey();
//! let ix = system_transfer(pubkey, recipient, 1_000_000);
//! let msg = Message::compile(pubkey, &[ix], blockhash)?;
//! let tx = Transaction::sign(msg, &[&se])?;
//! ```
//!
//! # Protocol overview
//!
//! Each APDU command is wrapped in a T=1 I-block:
//!
//! ```text
//! NAD | PCB | LEN | <APDU payload…> | LRC
//! ```
//!
//! The SE05x responds with a matching I-block containing the APDU
//! response and a two-byte status word (SW1‖SW2 = `0x9000` on success).

use crate::signer::Signer;
use crate::types::{Pubkey, Signature, SdkError, Result};

// ── I²C / T=1 constants ──────────────────────────────────────────────

/// Default SE05x I²C address.
const I2C_ADDR: u8 = 0x48;

/// NAD byte: host → SE05x.
const NAD_TX: u8 = 0x5A;

/// Maximum APDU response buffer size.
const MAX_RSP: usize = 256;

// ── APDU constants (NXP AN12413) ─────────────────────────────────────

/// Proprietary CLA byte.
const CLA: u8 = 0x80;

/// INS codes.
mod ins {
    /// Write / create / generate a secure object.
    pub const WRITE: u8 = 0x01;
    /// Read a secure object.
    pub const READ: u8 = 0x02;
    /// Cryptographic operation (sign, verify, …).
    pub const CRYPTO: u8 = 0x04;
    /// Management (delete, …).
    pub const MGMT: u8 = 0x03;
}

/// P1 variants.
mod p1 {
    /// EC key object (write / generate).
    pub const EC: u8 = 0x12;
    /// Key pair generation (used with EC).
    pub const KEY_PAIR: u8 = 0x60;
    /// Signature operation.
    pub const SIGNATURE: u8 = 0x21;
}

/// P2 variants.
mod p2 {
    /// Generate a new key pair.
    pub const GENERATE: u8 = 0x03;
    /// EdDSA PureEdDSA algorithm.
    pub const EDDSA: u8 = 0xA3;
    /// Default / none.
    pub const DEFAULT: u8 = 0x00;
}

/// Simple-TLV tag values.
mod tag {
    /// TAG_1 — object identifier (4 bytes).
    pub const OBJ_ID: u8 = 0x41;
    /// TAG_2 — offset (2 bytes) or secondary data.
    pub const OFFSET: u8 = 0x42;
    /// TAG_3 — EC curve identifier / length.
    pub const CURVE: u8 = 0x43;
    /// TAG_4 — data payload.
    pub const DATA: u8 = 0x44;
}

/// SE05x EC curve identifier for Ed25519.
const CURVE_ED25519: u8 = 0x40;

/// APDU success status word.
const SW_SUCCESS: u16 = 0x9000;

// ── TLV helpers ──────────────────────────────────────────────────────

/// Encode a Simple-TLV (tag + length + value) and push onto `buf`.
fn tlv_push(buf: &mut [u8], pos: &mut usize, tag: u8, value: &[u8]) {
    buf[*pos] = tag;
    *pos += 1;
    let len = value.len();
    if len < 0x80 {
        buf[*pos] = len as u8;
        *pos += 1;
    } else if len <= 0xFF {
        buf[*pos] = 0x81;
        buf[*pos + 1] = len as u8;
        *pos += 2;
    } else {
        buf[*pos] = 0x82;
        buf[*pos + 1] = (len >> 8) as u8;
        buf[*pos + 2] = len as u8;
        *pos += 3;
    }
    buf[*pos..*pos + len].copy_from_slice(value);
    *pos += len;
}

/// Parse a single TLV from `data[pos..]`. Returns `(tag, value_slice, new_pos)`.
fn tlv_parse<'a>(data: &'a [u8], pos: &mut usize) -> Result<(u8, &'a [u8])> {
    if *pos >= data.len() {
        return Err(SdkError::Deserialize);
    }
    let t = data[*pos];
    *pos += 1;
    if *pos >= data.len() {
        return Err(SdkError::Deserialize);
    }
    let len_byte = data[*pos];
    *pos += 1;
    let len = if len_byte < 0x80 {
        len_byte as usize
    } else if len_byte == 0x81 {
        if *pos >= data.len() {
            return Err(SdkError::Deserialize);
        }
        let l = data[*pos] as usize;
        *pos += 1;
        l
    } else if len_byte == 0x82 {
        if *pos + 1 >= data.len() {
            return Err(SdkError::Deserialize);
        }
        let l = ((data[*pos] as usize) << 8) | data[*pos + 1] as usize;
        *pos += 2;
        l
    } else {
        return Err(SdkError::Deserialize);
    };
    if *pos + len > data.len() {
        return Err(SdkError::Deserialize);
    }
    let val = &data[*pos..*pos + len];
    *pos += len;
    Ok((t, val))
}

// ── T=1 over I²C framing ────────────────────────────────────────────

/// Compute LRC (longitudinal redundancy check) for T=1 framing.
fn lrc(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc ^ b)
}

/// Build a T=1 I-block frame around `apdu`.
///
/// Layout: `NAD | PCB | LEN | <apdu…> | LRC`
fn frame_iblock(apdu: &[u8], seq: u8, buf: &mut [u8]) -> usize {
    let pcb = if seq & 1 == 0 { 0x00 } else { 0x40 };
    let len = apdu.len();
    buf[0] = NAD_TX;
    buf[1] = pcb;
    buf[2] = len as u8;
    buf[3..3 + len].copy_from_slice(apdu);
    buf[3 + len] = lrc(&buf[..3 + len]);
    4 + len
}

/// Parse a T=1 response frame. Returns the APDU payload (without LRC/framing).
fn parse_frame(buf: &[u8], len: usize) -> Result<&[u8]> {
    // Minimum frame: NAD + PCB + LEN + LRC = 4 bytes
    if len < 4 {
        return Err(SdkError::Deserialize);
    }
    let payload_len = buf[2] as usize;
    if 3 + payload_len + 1 > len {
        return Err(SdkError::Deserialize);
    }
    let expected_lrc = lrc(&buf[..3 + payload_len]);
    if buf[3 + payload_len] != expected_lrc {
        return Err(SdkError::Crypto);
    }
    Ok(&buf[3..3 + payload_len])
}

// ── SE05x driver ─────────────────────────────────────────────────────

/// NXP SE05x secure-element signer.
///
/// Stores an Ed25519 key pair inside the SE05x and performs signing
/// on-chip. The private key never leaves the secure element.
///
/// Interior mutability via `UnsafeCell` allows the [`Signer`] trait
/// (which takes `&self`) to perform I²C transactions. This is safe on
/// single-threaded bare-metal targets, which is the intended use case.
pub struct Se05xSigner<I2C> {
    inner: core::cell::UnsafeCell<Se05xInner<I2C>>,
    key_id: u32,
    pubkey: Pubkey,
}

struct Se05xInner<I2C> {
    i2c: I2C,
    addr: u8,
    seq: u8,
}

impl<I2C, E> Se05xSigner<I2C>
where
    I2C: embedded_hal::i2c::I2c<Error = E>,
{
    /// Create a new driver bound to the given I²C bus and SE05x object ID.
    ///
    /// The `key_id` is a 4-byte SE05x object identifier that will be used
    /// to store and reference the Ed25519 key pair. Choose an application-
    /// specific value (e.g., `0x0001_0001`).
    ///
    /// After construction, call [`generate_ed25519`](Self::generate_ed25519)
    /// to create a key, or [`init`](Self::init) to read an existing one.
    pub fn new(i2c: I2C, key_id: u32) -> Self {
        Self {
            inner: core::cell::UnsafeCell::new(Se05xInner {
                i2c,
                addr: I2C_ADDR,
                seq: 0,
            }),
            key_id,
            pubkey: Pubkey::new([0u8; 32]),
        }
    }

    /// Override the default I²C address (0x48).
    pub fn with_address(self, addr: u8) -> Self {
        // SAFETY: exclusive access during construction
        unsafe { &mut *self.inner.get() }.addr = addr;
        self
    }

    /// Get a mutable reference to the inner state.
    ///
    /// SAFETY: must only be called from a single-threaded context.
    fn inner_mut(&self) -> &mut Se05xInner<I2C> {
        unsafe { &mut *self.inner.get() }
    }

    // ── low-level I²C transport ──────────────────────────────────────

    /// Send an APDU command and receive the response.
    fn transceive(&self, apdu: &[u8]) -> Result<([u8; MAX_RSP], usize)> {
        let inner = self.inner_mut();
        let mut tx_buf = [0u8; MAX_RSP];
        let tx_len = frame_iblock(apdu, inner.seq, &mut tx_buf);
        inner.seq = inner.seq.wrapping_add(1);

        inner.i2c
            .write(inner.addr, &tx_buf[..tx_len])
            .map_err(|_| SdkError::Network)?;

        let mut rx_buf = [0u8; MAX_RSP];
        inner.i2c
            .read(inner.addr, &mut rx_buf)
            .map_err(|_| SdkError::Network)?;

        // Find actual response length from the frame header
        if rx_buf.len() < 4 {
            return Err(SdkError::Deserialize);
        }
        let payload_len = rx_buf[2] as usize;
        let frame_len = 3 + payload_len + 1; // NAD+PCB+LEN + payload + LRC

        Ok((rx_buf, frame_len))
    }

    /// Send an APDU and return the response data (status word checked).
    fn send_apdu(&self, apdu: &[u8]) -> Result<([u8; MAX_RSP], usize)> {
        let (rx_buf, frame_len) = self.transceive(apdu)?;
        let payload = parse_frame(&rx_buf, frame_len)?;

        if payload.len() < 2 {
            return Err(SdkError::Deserialize);
        }

        let sw = ((payload[payload.len() - 2] as u16) << 8)
            | payload[payload.len() - 1] as u16;
        if sw != SW_SUCCESS {
            return Err(SdkError::Crypto);
        }

        // Copy data portion (without SW) into output
        let data_len = payload.len() - 2;
        let mut out = [0u8; MAX_RSP];
        out[..data_len].copy_from_slice(&payload[..data_len]);
        Ok((out, data_len))
    }

    // ── APDU builders ────────────────────────────────────────────────

    /// Build an APDU: CLA INS P1 P2 Lc <data…>
    fn build_apdu(ins: u8, p1: u8, p2: u8, data: &[u8]) -> ([u8; MAX_RSP], usize) {
        let mut buf = [0u8; MAX_RSP];
        buf[0] = CLA;
        buf[1] = ins;
        buf[2] = p1;
        buf[3] = p2;
        let len = 5 + data.len();
        buf[4] = data.len() as u8;
        buf[5..5 + data.len()].copy_from_slice(data);
        (buf, len)
    }

    // ── public API ───────────────────────────────────────────────────

    /// Generate a new Ed25519 key pair inside the secure element.
    ///
    /// The key is stored under the object ID provided at construction.
    /// Overwrites any existing object with the same ID.
    /// After generation the cached public key is updated.
    pub fn generate_ed25519(&mut self) -> Result<Pubkey> {
        // Build TLV payload: OBJ_ID(4) + CURVE(1)
        let mut tlv = [0u8; 16];
        let mut pos = 0;
        let id_bytes = self.key_id.to_be_bytes();
        tlv_push(&mut tlv, &mut pos, tag::OBJ_ID, &id_bytes);
        tlv_push(&mut tlv, &mut pos, tag::CURVE, &[CURVE_ED25519]);

        let (apdu, alen) =
            Self::build_apdu(ins::WRITE, p1::EC | p1::KEY_PAIR, p2::GENERATE, &tlv[..pos]);
        self.send_apdu(&apdu[..alen])?;

        // Read back the public key
        self.read_public_key()
    }

    /// Read the Ed25519 public key for the stored object ID.
    ///
    /// Also updates the cached public key returned by [`pubkey()`](Signer::pubkey).
    pub fn read_public_key(&mut self) -> Result<Pubkey> {
        let pk = self.read_public_key_inner()?;
        self.pubkey = pk;
        Ok(pk)
    }

    /// Internal: read public key via APDU.
    fn read_public_key_inner(&self) -> Result<Pubkey> {
        let mut tlv = [0u8; 16];
        let mut pos = 0;
        let id_bytes = self.key_id.to_be_bytes();
        tlv_push(&mut tlv, &mut pos, tag::OBJ_ID, &id_bytes);
        // Offset 0, length 0 (read all)
        tlv_push(&mut tlv, &mut pos, tag::OFFSET, &[0x00, 0x00]);
        tlv_push(&mut tlv, &mut pos, tag::CURVE, &[0x00, 0x00]);

        let (apdu, alen) =
            Self::build_apdu(ins::READ, p2::DEFAULT, p2::DEFAULT, &tlv[..pos]);
        let (rsp, rsp_len) = self.send_apdu(&apdu[..alen])?;

        // Response contains TLV with the public key
        let data = &rsp[..rsp_len];
        let mut p = 0;
        while p < data.len() {
            let (t, val) = tlv_parse(data, &mut p)?;
            if t == tag::DATA {
                if val.len() != 32 {
                    return Err(SdkError::Crypto);
                }
                let mut pk = [0u8; 32];
                pk.copy_from_slice(val);
                return Ok(Pubkey::new(pk));
            }
        }

        Err(SdkError::Deserialize)
    }

    /// Read the Ed25519 public key and initialize the cached pubkey.
    ///
    /// Call this instead of [`generate_ed25519`](Self::generate_ed25519)
    /// when the key already exists on the secure element.
    pub fn init(&mut self) -> Result<Pubkey> {
        self.read_public_key()
    }

    /// Sign `message` using the Ed25519 key stored in the secure element.
    pub fn sign_message(&self, message: &[u8]) -> Result<Signature> {
        let mut tlv = [0u8; MAX_RSP];
        let mut pos = 0;
        let id_bytes = self.key_id.to_be_bytes();
        tlv_push(&mut tlv, &mut pos, tag::OBJ_ID, &id_bytes);
        tlv_push(&mut tlv, &mut pos, tag::DATA, message);

        let (apdu, alen) =
            Self::build_apdu(ins::CRYPTO, p1::SIGNATURE, p2::EDDSA, &tlv[..pos]);
        let (rsp, rsp_len) = self.send_apdu(&apdu[..alen])?;

        // Response contains the 64-byte Ed25519 signature
        let data = &rsp[..rsp_len];
        let mut p = 0;
        while p < data.len() {
            let (t, val) = tlv_parse(data, &mut p)?;
            if t == tag::DATA {
                if val.len() != 64 {
                    return Err(SdkError::Crypto);
                }
                let mut sig = [0u8; 64];
                sig.copy_from_slice(val);
                return Ok(Signature::new(sig));
            }
        }

        Err(SdkError::Deserialize)
    }

    /// Delete the Ed25519 key object from the secure element.
    pub fn delete_key(&mut self) -> Result<()> {
        let mut tlv = [0u8; 8];
        let mut pos = 0;
        let id_bytes = self.key_id.to_be_bytes();
        tlv_push(&mut tlv, &mut pos, tag::OBJ_ID, &id_bytes);

        let (apdu, alen) =
            Self::build_apdu(ins::MGMT, p2::DEFAULT, p2::DEFAULT, &tlv[..pos]);
        self.send_apdu(&apdu[..alen])?;
        self.pubkey = Pubkey::new([0u8; 32]);
        Ok(())
    }

    /// Return the underlying I²C bus.
    pub fn release(self) -> I2C {
        self.inner.into_inner().i2c
    }
}

impl<I2C, E> Signer for Se05xSigner<I2C>
where
    I2C: embedded_hal::i2c::I2c<Error = E>,
{
    fn pubkey(&self) -> Pubkey {
        self.pubkey
    }

    fn sign(&self, message: &[u8]) -> Result<Signature> {
        self.sign_message(message)
    }
}

// ── tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lrc_computation() {
        assert_eq!(lrc(&[0x5A, 0x00, 0x03, 0xAA, 0xBB, 0xCC]), 0x5A ^ 0x00 ^ 0x03 ^ 0xAA ^ 0xBB ^ 0xCC);
        assert_eq!(lrc(&[]), 0);
        assert_eq!(lrc(&[0xFF]), 0xFF);
    }

    #[test]
    fn tlv_push_short_length() {
        let mut buf = [0u8; 16];
        let mut pos = 0;
        tlv_push(&mut buf, &mut pos, 0x41, &[0x00, 0x01, 0x00, 0x01]);
        assert_eq!(pos, 6); // tag(1) + len(1) + value(4)
        assert_eq!(buf[0], 0x41);
        assert_eq!(buf[1], 0x04);
        assert_eq!(&buf[2..6], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn tlv_roundtrip() {
        let mut buf = [0u8; 32];
        let mut pos = 0;
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        tlv_push(&mut buf, &mut pos, 0x44, &data);

        let mut p = 0;
        let (t, val) = tlv_parse(&buf[..pos], &mut p).unwrap();
        assert_eq!(t, 0x44);
        assert_eq!(val, &data);
        assert_eq!(p, pos);
    }

    #[test]
    fn frame_iblock_structure() {
        let apdu = [CLA, 0x01, 0x72, 0x03, 0x06, 0x41, 0x04, 0x00, 0x01, 0x00, 0x01];
        let mut buf = [0u8; 64];
        let len = frame_iblock(&apdu, 0, &mut buf);

        assert_eq!(buf[0], NAD_TX);    // NAD
        assert_eq!(buf[1], 0x00);      // PCB (seq 0)
        assert_eq!(buf[2], apdu.len() as u8); // LEN
        assert_eq!(&buf[3..3 + apdu.len()], &apdu);
        // LRC covers NAD+PCB+LEN+payload
        assert_eq!(buf[3 + apdu.len()], lrc(&buf[..3 + apdu.len()]));
        assert_eq!(len, 4 + apdu.len());
    }

    #[test]
    fn frame_iblock_sequence_toggle() {
        let apdu = [0x80, 0x01];
        let mut buf = [0u8; 16];

        frame_iblock(&apdu, 0, &mut buf);
        assert_eq!(buf[1], 0x00); // PCB seq=0

        frame_iblock(&apdu, 1, &mut buf);
        assert_eq!(buf[1], 0x40); // PCB seq=1
    }

    #[test]
    fn parse_frame_valid() {
        // Build a frame manually: NAD=0xA5, PCB=0x00, LEN=2, payload=[0x90, 0x00], LRC
        let _payload = [0x90u8, 0x00];
        let mut frame = [0u8; 8];
        frame[0] = 0xA5;
        frame[1] = 0x00;
        frame[2] = 0x02;
        frame[3] = 0x90;
        frame[4] = 0x00;
        frame[5] = lrc(&frame[..5]);

        let result = parse_frame(&frame, 6).unwrap();
        assert_eq!(result, &[0x90, 0x00]);
    }

    #[test]
    fn parse_frame_bad_lrc() {
        let mut frame = [0u8; 8];
        frame[0] = 0xA5;
        frame[1] = 0x00;
        frame[2] = 0x02;
        frame[3] = 0x90;
        frame[4] = 0x00;
        frame[5] = 0xFF; // wrong LRC

        assert!(parse_frame(&frame, 6).is_err());
    }

    #[test]
    fn parse_frame_too_short() {
        assert!(parse_frame(&[0x00, 0x00, 0x00], 3).is_err());
    }

    #[test]
    fn build_apdu_structure() {
        let data = [0x41, 0x04, 0x00, 0x01, 0x00, 0x01];
        let (buf, len) = Se05xSigner::<MockI2c>::build_apdu(ins::WRITE, p1::EC | p1::KEY_PAIR, p2::GENERATE, &data);
        assert_eq!(buf[0], CLA);
        assert_eq!(buf[1], ins::WRITE);
        assert_eq!(buf[2], p1::EC | p1::KEY_PAIR);
        assert_eq!(buf[3], p2::GENERATE);
        assert_eq!(buf[4], data.len() as u8);
        assert_eq!(&buf[5..5 + data.len()], &data);
        assert_eq!(len, 5 + data.len());
    }

    // ── Mock I²C for unit tests ──────────────────────────────────────

    /// Minimal mock I²C that records writes and returns pre-set responses.
    struct MockI2c {
        /// Pre-loaded response frames (outer = sequential calls).
        responses: alloc::vec::Vec<alloc::vec::Vec<u8>>,
        call_idx: usize,
    }

    impl MockI2c {
        fn new(responses: alloc::vec::Vec<alloc::vec::Vec<u8>>) -> Self {
            Self { responses, call_idx: 0 }
        }
    }

    #[derive(Debug)]
    struct MockError;

    impl embedded_hal::i2c::Error for MockError {
        fn kind(&self) -> embedded_hal::i2c::ErrorKind {
            embedded_hal::i2c::ErrorKind::Other
        }
    }

    impl embedded_hal::i2c::ErrorType for MockI2c {
        type Error = MockError;
    }

    impl embedded_hal::i2c::I2c for MockI2c {
        fn transaction(
            &mut self,
            _address: u8,
            operations: &mut [embedded_hal::i2c::Operation<'_>],
        ) -> core::result::Result<(), MockError> {
            for op in operations {
                match op {
                    embedded_hal::i2c::Operation::Write(_) => {}
                    embedded_hal::i2c::Operation::Read(buf) => {
                        if self.call_idx < self.responses.len() {
                            let rsp = &self.responses[self.call_idx];
                            let copy_len = buf.len().min(rsp.len());
                            buf[..copy_len].copy_from_slice(&rsp[..copy_len]);
                        }
                    }
                }
            }
            self.call_idx += 1;
            Ok(())
        }

        fn read(&mut self, _address: u8, read: &mut [u8]) -> core::result::Result<(), MockError> {
            if self.call_idx < self.responses.len() {
                let rsp = &self.responses[self.call_idx];
                let copy_len = read.len().min(rsp.len());
                read[..copy_len].copy_from_slice(&rsp[..copy_len]);
            }
            self.call_idx += 1;
            Ok(())
        }

        fn write(&mut self, _address: u8, _write: &[u8]) -> core::result::Result<(), MockError> {
            Ok(())
        }

        fn write_read(
            &mut self,
            _address: u8,
            _write: &[u8],
            read: &mut [u8],
        ) -> core::result::Result<(), MockError> {
            if self.call_idx < self.responses.len() {
                let rsp = &self.responses[self.call_idx];
                let copy_len = read.len().min(rsp.len());
                read[..copy_len].copy_from_slice(&rsp[..copy_len]);
            }
            self.call_idx += 1;
            Ok(())
        }
    }

    /// Helper: build a T=1 response frame with the given APDU response payload.
    fn mock_frame(apdu_response: &[u8]) -> alloc::vec::Vec<u8> {
        let mut frame = alloc::vec::Vec::with_capacity(4 + apdu_response.len());
        frame.push(0xA5); // NAD (SE05x → host)
        frame.push(0x00); // PCB
        frame.push(apdu_response.len() as u8);
        frame.extend_from_slice(apdu_response);
        let l = lrc(&frame);
        frame.push(l);
        frame
    }

    #[test]
    fn se05x_signer_new_defaults() {
        let mock = MockI2c::new(alloc::vec::Vec::new());
        let signer = Se05xSigner::new(mock, 0x0001_0001);
        assert_eq!(signer.key_id, 0x0001_0001);
        assert_eq!(signer.pubkey(), Pubkey::new([0u8; 32]));
    }

    #[test]
    fn se05x_signer_custom_address() {
        let mock = MockI2c::new(alloc::vec::Vec::new());
        let signer = Se05xSigner::new(mock, 0x0001_0001).with_address(0x50);
        let inner = unsafe { &*signer.inner.get() };
        assert_eq!(inner.addr, 0x50);
    }

    #[test]
    fn se05x_read_public_key_mock() {
        // Prepare a mock response containing a TLV with a 32-byte public key
        let fake_pk = [0x42u8; 32];
        let mut apdu_rsp = alloc::vec::Vec::new();
        // TLV: tag=0x44, len=32, value=fake_pk
        apdu_rsp.push(tag::DATA);
        apdu_rsp.push(32);
        apdu_rsp.extend_from_slice(&fake_pk);
        // SW = 0x9000
        apdu_rsp.push(0x90);
        apdu_rsp.push(0x00);

        let frame = mock_frame(&apdu_rsp);

        // The read_public_key sends: write (APDU), read (response)
        // Mock: first call is write (ignored), second call is read
        let mock = MockI2c::new(alloc::vec![frame]);
        let mut signer = Se05xSigner::new(mock, 0x0001_0001);
        let pk = signer.read_public_key().unwrap();
        assert_eq!(pk, Pubkey::new(fake_pk));
        assert_eq!(signer.pubkey(), Pubkey::new(fake_pk));
    }

    #[test]
    fn se05x_sign_message_mock() {
        // Prepare a mock response containing a TLV with a 64-byte signature
        let fake_sig = [0xAB; 64];
        let mut apdu_rsp = alloc::vec::Vec::new();
        apdu_rsp.push(tag::DATA);
        apdu_rsp.push(64);
        apdu_rsp.extend_from_slice(&fake_sig);
        apdu_rsp.push(0x90);
        apdu_rsp.push(0x00);

        let frame = mock_frame(&apdu_rsp);
        let mock = MockI2c::new(alloc::vec![frame]);
        let signer = Se05xSigner::new(mock, 0x0001_0001);
        let sig = signer.sign_message(b"test message").unwrap();
        assert_eq!(sig, Signature::new(fake_sig));
    }

    #[test]
    fn se05x_send_apdu_bad_sw() {
        // Response with SW = 0x6A82 (file not found)
        let apdu_rsp = [0x6A, 0x82];
        let frame = mock_frame(&apdu_rsp);
        let mock = MockI2c::new(alloc::vec![frame]);
        let mut signer = Se05xSigner::new(mock, 0x0001_0001);
        assert!(signer.read_public_key().is_err());
    }
}
