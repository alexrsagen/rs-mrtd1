use crate::error::BoxResult;
use crate::crypto::padding::pad;
use crate::crypto::des::mac;
use crate::crypto::tdes::encrypt_pad;
use super::owned::ApduCommand as OwnedApduCommand;
use iso7816_tlv::TlvError;
use iso7816_tlv::ber as tlv;

#[derive(Debug, PartialEq, Eq)]
pub struct ApduCommand<'a> {
	pub cla: u8,
	pub ins: u8,
	pub p1: u8,
	pub p2: u8,
	pub data: &'a [u8],
	pub rx_len: usize,
}

impl<'a> ApduCommand<'a> {
	pub fn len(&self) -> usize {
		4 + self.lc_len() + self.le_len()
	}

	#[inline]
	fn lc_len(&self) -> usize {
		let len = self.data.len();
		if len == 0 {
			0
		} else if len < 256 {
			1
		} else {
			3
		}
	}

	fn extend_buf_with_lc(&self, buf: &mut Vec<u8>) {
		let len = self.data.len();
		if len == 0 {
			return
		}
		if len < 256 {
			buf.extend_from_slice(&[(len & 0xFF) as u8]);
		} else {
			buf.extend_from_slice(&[0x00]);
			buf.extend_from_slice(&((len & 0xFFFF) as u16).to_be_bytes());
		}
	}

	#[inline]
	fn le_len(&self) -> usize {
		let lc_extended = self.lc_len() == 3;
		if self.rx_len == 0 {
			0
		} else if self.rx_len <= 256 {
			1
		} else if self.rx_len <= 65536 && lc_extended {
			2
		} else {
			3
		}
	}

	fn extend_buf_with_le(&self, buf: &mut Vec<u8>) {
		let lc_extended = self.lc_len() == 3;
		if self.rx_len == 0 {
			return
		}
		if self.rx_len <= 256 {
			buf.extend_from_slice(&[(self.rx_len & 0xFF) as u8]);
		} else if self.rx_len <= 65536 && lc_extended {
			buf.extend_from_slice(&((self.rx_len & 0xFFFF) as u16).to_be_bytes());
		} else {
			buf.extend_from_slice(&[0x00]);
			buf.extend_from_slice(&((self.rx_len & 0xFFFF) as u16).to_be_bytes());
		}
	}

	pub fn to_vec(&self) -> Vec<u8> {
		let mut buf = Vec::with_capacity(self.len());
		buf.resize(4, 0);
		buf[0] = self.cla;
		buf[1] = self.ins;
		buf[2] = self.p1;
		buf[3] = self.p2;
		self.extend_buf_with_lc(&mut buf);
		buf.extend_from_slice(&self.data);
		self.extend_buf_with_le(&mut buf);
		buf
	}

	pub fn to_protected(&self, ks_enc: &[u8], ks_mac: &[u8], ssc: &mut u64) -> BoxResult<OwnedApduCommand> {
		// a) Mask class byte and pad command header
		let cmd_header = pad(Self { cla: 0x0C, ins: self.ins, p1: self.p1, p2: self.p2, data: &[], rx_len: 0 }.to_vec().as_slice());

		// Build [DO'97']
		let le_len = self.le_len();
		let tlv_le = if le_len > 0 {
			let mut le = Vec::with_capacity(le_len);
			self.extend_buf_with_le(&mut le);
			tlv::Tlv::new(tlv::Tag::try_from(0x97).map_err(|e: TlvError| e.to_string())?, tlv::Value::Primitive(le)).map_err(|e: TlvError| e.to_string())?.to_vec()
		} else {
			Vec::new()
		};

		let tlv_data = if self.data.len() > 0 {
			// b) Pad data
			// c) Encrypt data with KSEnc
			let data = encrypt_pad(self.data, ks_enc)?;

			// d) Build [DO'85' or DO'87']
			// In case INS is even, [DO'87'] SHALL be used, and in case INS is odd, [DO'85'] SHALL be used
			let (tlv_tag, data) = if self.ins % 2 == 0 {
				let mut padding_indicator_and_data = Vec::with_capacity(data.len() + 1);
				padding_indicator_and_data.extend_from_slice(&[0x01]);
				padding_indicator_and_data.extend_from_slice(&data);
				(tlv::Tag::try_from(0x87).map_err(|e: TlvError| e.to_string())?, padding_indicator_and_data)
			} else {
				(tlv::Tag::try_from(0x85).map_err(|e: TlvError| e.to_string())?, data)
			};

			tlv::Tlv::new(tlv_tag, tlv::Value::Primitive(data)).map_err(|e: TlvError| e.to_string())?.to_vec()
		} else {
			Vec::new()
		};

		// e) Concatenate CmdHeader [DO'85' or DO'87'] [DO'97']
		let mut m = Vec::with_capacity(cmd_header.len() + tlv_data.len() + tlv_le.len());
		m.extend_from_slice(&cmd_header);
		m.extend_from_slice(&tlv_data);
		m.extend_from_slice(&tlv_le);

		// f) Compute MAC of M

		// i) Increment SSC with 1
		*ssc += 1;

		// ii) Concatenate SSC and [DO'99']
		let ssc_bytes = ssc.to_be_bytes();
		let mut n = Vec::with_capacity(ssc_bytes.len() + m.len());
		n.extend_from_slice(&ssc_bytes);
		n.extend_from_slice(&m);

		// iii) Compute MAC over N with KSMAC
		let cc = mac(&n, ks_mac)?;

		// g) Build [DO'8E']
		let tlv_mac = tlv::Tlv::new(tlv::Tag::try_from(0x8E).map_err(|e: TlvError| e.to_string())?, tlv::Value::Primitive(cc)).map_err(|e: TlvError| e.to_string())?.to_vec();

		// Build protected APDU data: [DO'85' or DO'87'] [DO'97'] [DO'8E']
		let mut protected_apdu_data = Vec::with_capacity(tlv_data.len() + tlv_le.len() + tlv_mac.len());
		protected_apdu_data.extend_from_slice(&tlv_data);
		protected_apdu_data.extend_from_slice(&tlv_le);
		protected_apdu_data.extend_from_slice(&tlv_mac);

		// Build protected APDU: CmdHeader Lc' [DO'85' or DO'87'] [DO'97'] [DO'8E'] ['00' or '00 00']
		// - rx_len = 256   ['00']    for standard length
		// - rx_len = 65536 ['00 00'] for extended length
		Ok(OwnedApduCommand { cla: 0x0C, ins: self.ins, p1: self.p1, p2: self.p2, data: protected_apdu_data, rx_len: 256 })
	}
}

impl<'a> From<&'a ApduCommand<'a>> for Vec<u8> {
	fn from(apdu: &'a ApduCommand<'a>) -> Self {
		apdu.to_vec()
	}
}