use crate::error::BoxResult;
use crate::apdu::command::borrowed::ApduCommand;
use crate::apdu::response::owned::ApduResponse;

pub type DataGroup = u8;
pub type Tag = u8;
pub type FileId = u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct File {
	pub tag: Tag,
	pub dg: DataGroup,
	pub fileid: FileId,
	pub name: &'static str,
	pub desc: &'static str,
	pub pace: bool,
	pub eac: bool,
	pub req: bool,
	pub fast: bool,
}

pub const EF_COM: File = File { tag: 0x60, dg: 0, fileid: 0x011E, name: "EF_COM", desc: "Header and Data Group Presence Information", pace: false, eac: false, req: true, fast: true };
pub const EF_SOD: File = File { tag: 0x77, dg: 0, fileid: 0x011D, name: "EF_SOD", desc: "Document Security Object", pace: false, eac: false, req: false, fast: false };
pub const EF_CARDACCESS: File = File { tag: 0xFF, dg: 0, fileid: 0x011C, name: "EF_CardAccess", desc: "PACE SecurityInfos", pace: true, eac: false, req: true, fast: true };
pub const EF_CARDSECURITY: File = File { tag: 0xFF, dg: 0, fileid: 0x011D, name: "EF_CardSecurity", desc: "PACE SecurityInfos for Chip Authentication Mapping", pace: true, eac: false, req: false, fast: true };
pub const EF_DG14: File = File { tag: 0x6E, dg: 14, fileid: 0x010E, name: "EF_DG14", desc: "Security Options", pace: false, eac: false, req: false, fast: true };
pub const EF_DG15: File = File { tag: 0x6F, dg: 15, fileid: 0x010F, name: "EF_DG15", desc: "Active Authentication Public Key Info", pace: false, eac: false, req: false, fast: true };
pub const EF_DG1: File = File { tag: 0x61, dg: 1, fileid: 0x0101, name: "EF_DG1", desc: "Details recorded in MRZ", pace: false, eac: false, req: true, fast: true };
pub const EF_DG2: File = File { tag: 0x75, dg: 2, fileid: 0x0102, name: "EF_DG2", desc: "Encoded Face", pace: false, eac: false, req: true, fast: false };
pub const EF_DG3: File = File { tag: 0x63, dg: 3, fileid: 0x0103, name: "EF_DG3", desc: "Encoded Finger(s)", pace: false, eac: true, req: false, fast: false };
pub const EF_DG4: File = File { tag: 0x76, dg: 4, fileid: 0x0104, name: "EF_DG4", desc: "Encoded Eye(s)", pace: false, eac: true, req: false, fast: false };
pub const EF_DG5: File = File { tag: 0x65, dg: 5, fileid: 0x0105, name: "EF_DG5", desc: "Displayed Portrait", pace: false, eac: false, req: false, fast: false };
pub const EF_DG6: File = File { tag: 0x66, dg: 6, fileid: 0x0106, name: "EF_DG6", desc: "Reserved for Future Use", pace: false, eac: false, req: false, fast: false };
pub const EF_DG7: File = File { tag: 0x67, dg: 7, fileid: 0x0107, name: "EF_DG7", desc: "Displayed Signature or Usual Mark", pace: false, eac: false, req: false, fast: false };
pub const EF_DG8: File = File { tag: 0x68, dg: 8, fileid: 0x0108, name: "EF_DG8", desc: "Data Feature(s)", pace: false, eac: false, req: false, fast: true };
pub const EF_DG9: File = File { tag: 0x69, dg: 9, fileid: 0x0109, name: "EF_DG9", desc: "Structure Feature(s)", pace: false, eac: false, req: false, fast: true };
pub const EF_DG10: File = File { tag: 0x6A, dg: 10, fileid: 0x010A, name: "EF_DG10", desc: "Substance Feature(s)", pace: false, eac: false, req: false, fast: true };
pub const EF_DG11: File = File { tag: 0x6B, dg: 11, fileid: 0x010B, name: "EF_DG11", desc: "Additional Personal Detail(s)", pace: false, eac: false, req: false, fast: true };
pub const EF_DG12: File = File { tag: 0x6C, dg: 12, fileid: 0x010C, name: "EF_DG12", desc: "Additional Document Detail(s)", pace: false, eac: false, req: false, fast: true };
pub const EF_DG13: File = File { tag: 0x6D, dg: 13, fileid: 0x010D, name: "EF_DG13", desc: "Optional Detail(s)", pace: false, eac: false, req: false, fast: true };
pub const EF_DG16: File = File { tag: 0x70, dg: 16, fileid: 0x0110, name: "EF_DG16", desc: "Person(s) to Notify", pace: false, eac: false, req: false, fast: true };
pub const FILES: [File; 20] = [ EF_COM, EF_SOD, EF_CARDACCESS, EF_CARDSECURITY, EF_DG14, EF_DG15, EF_DG1, EF_DG2, EF_DG3, EF_DG4, EF_DG5, EF_DG6, EF_DG7, EF_DG8, EF_DG9, EF_DG10, EF_DG11, EF_DG12, EF_DG13, EF_DG16 ];

const HEADER_LEN: usize = 4;
const MAX_READ: usize = 100;
#[cfg(feature = "nfc1")]
pub fn read_file(device: &mut nfc1::Device, ks_mac: &[u8], ks_enc: &[u8], ssc: &mut u64, file: &File) -> BoxResult<Vec<u8>> {
	let mut offset = 0;

	// 1. Select EF.COM
	let fileid = file.fileid.to_be_bytes();
	let apdu = ApduCommand { cla: 0x00, ins: 0xA4, p1: 0x02, p2: 0x0C, data: &fileid, rx_len: 0 }.to_protected(ks_enc, ks_mac, ssc)?.to_vec();
	let res = ApduResponse::from_protected(device.initiator_transceive_bytes(&apdu, 16, nfc1::Timeout::None)?, ks_mac, ks_enc, ssc)?;

	// 2. Read Binary of first four bytes
	let apdu = apdu_read_binary(HEADER_LEN, offset).to_protected(ks_enc, ks_mac, ssc)?.to_vec();
	let res = ApduResponse::from_protected(device.initiator_transceive_bytes(&apdu, 27, nfc1::Timeout::None)?, ks_mac, ks_enc, ssc)?;
	if res.data.len() != HEADER_LEN {
		return Err(format!("Invalid response data length {}, expected {}", res.data.len(), HEADER_LEN).into());
	}

	// j) Determine length of structure
	let mut len = 0usize;
	let x = res.data[1];
	if x & 0x80 == 0 {
		len = x as usize;
	} else {
		let n_bytes = x as usize & 0x7f;
		if n_bytes > HEADER_LEN {
			return Err("Invalid file length".into());
		}
		for n in 0..n_bytes {
			let x = res.data[2+n];
			len = len << 8 | x as usize;
		}
	}

	// create buffer to store all data
	let mut data = Vec::with_capacity(len);
	len -= HEADER_LEN;
	offset += HEADER_LEN;
	data.extend_from_slice(&res.data);

	// 3. Read Binary of remaining (tlv_size)-4 bytes from offset 4
	while len > 0 {
		let chunk_len = if len > MAX_READ {
			MAX_READ
		} else {
			len
		};
		let apdu = apdu_read_binary(chunk_len, offset).to_protected(ks_enc, ks_mac, ssc)?.to_vec();
		let res = ApduResponse::from_protected(device.initiator_transceive_bytes(&apdu, 123, nfc1::Timeout::None)?, ks_mac, ks_enc, ssc)?;
		if res.data.len() != chunk_len {
			return Err(format!("Invalid response data length {}, expected {}", res.data.len(), chunk_len).into());
		}
		len -= chunk_len;
		offset += chunk_len;
		data.extend_from_slice(&res.data);
	}

	Ok(data)
}

pub fn apdu_read_binary<'a>(rx_len: usize, offset: usize) -> ApduCommand<'a> {
	let offset = (offset as u16).to_be_bytes();
	ApduCommand { cla: 0x00, ins: 0xB0, p1: offset[0], p2: offset[1], data: &[], rx_len }
}