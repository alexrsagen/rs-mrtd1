use crate::error::BoxResult;
use crate::crypto::des::mac;
use crate::crypto::tdes::decrypt_unpad;
use hex_fmt::HexFmt;
use iso7816_tlv::ber as tlv;


#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ApduResponseTrailer {
	pub sw1: u8,
	pub sw2: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduResponse {
	pub data: Vec<u8>,
	pub trailer: ApduResponseTrailer,
}

impl ApduResponse {
	pub fn from_protected(input: Vec<u8>, ks_mac: &[u8], ks_enc: &[u8], ssc: &mut u64) -> BoxResult<Self> {
		let res = ApduResponse::from(input);
		if res.trailer != TRAILER_OK {
			return Err(format!("SM APDU failed: {}", res.trailer).into());
		}

		// extract TLV parts from response
		let tlv_parts = tlv::Tlv::parse_all(&res.data);
		let tlv_status = tlv_parts.iter().find(|part| Into::<u64>::into(part.tag().clone()) == 0x99);
		let tlv_data = tlv_parts.iter().find(|part| [0x85_u64, 0x87_u64].contains(&Into::<u64>::into(part.tag().clone())));
		let tlv_mac = tlv_parts.iter().find(|part| Into::<u64>::into(part.tag().clone()) == 0x8E);

		let status = if let (Some(tlv_status), Some(tlv::Value::Primitive(status_value)), Some(tlv::Value::Primitive(mac_value))) = (tlv_status, tlv_status.map(|t| t.value()), tlv_mac.map(|t| t.value())) {
			let tlv_status_bytes = tlv_status.to_vec();
			let tlv_data_bytes = if let Some(tlv_data) = tlv_data {
				tlv_data.to_vec()
			} else {
				Vec::new()
			};

			// j) Verify RAPDU CC by computing MAC of [DO'99']

			// i) Increment SSC with 1
			*ssc += 1;

			// ii) Concatenate SSC [DO'85' or DO'87'] [DO'99']
			let ssc_bytes = ssc.to_be_bytes();
			let mut k = Vec::with_capacity(ssc_bytes.len() + tlv_data_bytes.len() + tlv_status_bytes.len());
			k.extend_from_slice(&ssc_bytes);
			k.extend_from_slice(&tlv_data_bytes);
			k.extend_from_slice(&tlv_status_bytes);

			// iii) Compute MAC with KSMAC
			let cc = mac(&k, ks_mac)?;

			// v) Compare CC' with data of [DO'8E'] of RAPDU
			if &cc != mac_value {
				return Err(format!("Invalid MAC {}, expected {}", HexFmt(mac_value), HexFmt(cc)).into());
			}

			status_value
		} else {
			return Err("Invalid TLV".into());
		};

		let res_apdu = if let (Some(tag), Some(tlv::Value::Primitive(data))) = (tlv_data.map(|t| t.tag()), tlv_data.map(|t| t.value())) {
			let data = if Into::<u64>::into(tag.clone()) == 0x87 {
				decrypt_unpad(&data[1..], ks_enc)?
			} else {
				decrypt_unpad(&data, ks_enc)?
			};
			let mut res_apdu = Vec::with_capacity(data.len() + status.len());
			res_apdu.extend_from_slice(&data);
			res_apdu.extend_from_slice(status);
			res_apdu
		} else {
			status.clone()
		};

		Ok(ApduResponse::from(res_apdu))
	}
}

impl From<Vec<u8>> for ApduResponse {
	fn from(mut data: Vec<u8>) -> Self {
		if data.len() < 2 {
			Self { data, trailer: ApduResponseTrailer::default() }
		} else {
			let sw2 = data[data.len()-1];
			let sw1 = data[data.len()-2];
			data.resize(data.len()-2, 0);
			Self { data, trailer: ApduResponseTrailer { sw1, sw2 } }
		}
	}
}

impl std::fmt::Display for ApduResponseTrailer {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "(SW1: 0x{:02X}, SW2: 0x{:02X})", self.sw1, self.sw2)
	}
}

impl std::fmt::Display for ApduResponse {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if self.data.len() > 0 {
			write!(f, "{} {}", HexFmt(&self.data), &self.trailer)
		} else {
			self.trailer.fmt(f)
		}
	}
}

pub const TRAILER_OK: ApduResponseTrailer = ApduResponseTrailer { sw1: 0x90, sw2: 0x00 };
pub const TRAILER_WRONG_LEN: ApduResponseTrailer = ApduResponseTrailer { sw1: 0x67, sw2: 0x00 };
pub const TRAILER_WRONG_CLA: ApduResponseTrailer = ApduResponseTrailer { sw1: 0x68, sw2: 0x00 };
pub const TRAILER_FUNCTION_NOT_SUPPORTED: ApduResponseTrailer = ApduResponseTrailer { sw1: 0x6A, sw2: 0x81 };
pub const TRAILER_WRONG_P1_P2: ApduResponseTrailer = ApduResponseTrailer { sw1: 0x6B, sw2: 0x00 };
pub const TRAILER_WRONG_SM_OBJECTS: ApduResponseTrailer = ApduResponseTrailer { sw1: 0x69, sw2: 0x88 };
pub const TRAILER_UNKNOWN: ApduResponseTrailer = ApduResponseTrailer { sw1: 0x6C, sw2: 0x00 };