use crate::error::BoxResult;
use crate::apdu::command::borrowed::ApduCommand;
use crate::apdu::response::owned::{ApduResponse, TRAILER_OK};
use std::time::Duration;
use crate::crypto::derive_key;
use crate::crypto::des::mac;
use crate::crypto::tdes::{encrypt, decrypt};
use crate::mrz::borrowed::{Mrz, MrzData};
use rand::RngCore;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
	pub ks_enc: Vec<u8>,
	pub ks_mac: Vec<u8>,
	pub ssc: u64,
}

#[cfg(feature = "nfc1")]
pub fn handshake(device: &mut nfc1::Device, mrz: &Mrz) -> BoxResult<SessionKeys> {
	let k_seed = mrz.derive_seed_key();
	let k_enc = derive_key(&k_seed, 1);
	let k_mac = derive_key(&k_seed, 2);

	// The following Basic Access Control (BAC) handshake is performed as per
	// ICAO 9303 MRTD v8 2021 Part 11, section 4.3.1 Protocol Specification
	let mut rng = rand::thread_rng();

	// Send initial select command
	let apdu = APDU_INITIAL_SELECT.to_vec();
	let initial_select_res = ApduResponse::from(device.initiator_transceive_bytes(&apdu, 2, nfc1::Timeout::Duration(Duration::from_millis(500)))?);
	if initial_select_res.trailer != TRAILER_OK {
		return Err("INITIAL SELECT failed".into());
	}

	// 1) The IFD requests a challenge RND.IC by sending the GET CHALLENGE command.
	// The IC generates and responds with a nonce RND.IC.
	let apdu = APDU_GET_CHALLENGE.to_vec();
	let get_challenge_res = ApduResponse::from(device.initiator_transceive_bytes(&apdu, 10, nfc1::Timeout::Duration(Duration::from_millis(500)))?);
	if get_challenge_res.trailer != TRAILER_OK {
		return Err("GET CHALLENGE failed".into());
	}

	// 2) The IFD performs the following operations:

	// a) generate a nonce RND.IFD and keying material K.IFD.
	let mut rnd_ifd = [0; 8];
	rng.fill_bytes(&mut rnd_ifd);
	let mut k_ifd = [0; 16];
	rng.fill_bytes(&mut k_ifd);

	// b) generate the concatenation S = RND.IFD || RND.IC || K.IFD
	let mut s = Vec::with_capacity(32);
	s.extend_from_slice(&rnd_ifd[0..8]);
	s.extend_from_slice(&get_challenge_res.data[0..8]);
	s.extend_from_slice(&k_ifd[0..16]);

	// c) compute the cryptogram EIFD = E(KEnc, S).
	let eifd = encrypt(&s, &k_enc)?;

	// d) compute the checksum MIFD = MAC(KMAC, EIFD)
	let mifd = mac(&eifd, &k_mac)?;

	// e) send the EXTERNAL AUTHENTICATE command with mutual authenticate function using the data EIFD || MIFD
	let mut eifd_mifd = Vec::with_capacity(eifd.len() + mifd.len());
	eifd_mifd.extend_from_slice(&eifd);
	eifd_mifd.extend_from_slice(&mifd);
	let apdu = apdu_external_authenticate(&eifd_mifd).to_vec();
	let auth_res = ApduResponse::from(device.initiator_transceive_bytes(&apdu, 42, nfc1::Timeout::None)?);
	if auth_res.trailer != TRAILER_OK {
		return Err("EXTERNAL AUTHENTICATE failed".into());
	}
	let (e_ic, m_ic) = auth_res.data.split_at(32);

	// 4) The IFD performs the following operations:

	// a) check the checksum MIC of the cryptogram EIC
	let expected_m_ic = mac(e_ic, &k_mac)?;
	if m_ic != expected_m_ic {
		return Err(format!("Invalid MAC of cryptogram EIC: Expected {:02x?}, got {:02x?}", expected_m_ic, m_ic).into());
	}

	// b) decrypt the cryptogram EIC
	let d_ic = decrypt(e_ic, &k_enc)?;

	// c) extract RND.IFD from R and check if IC returned the correct value
	let (rnd_ic, rnd_ifd_k_ic) = d_ic.split_at(8);
	let (rnd_ifd_ic, k_ic) = rnd_ifd_k_ic.split_at(8);
	if rnd_ifd_ic != rnd_ifd {
		return Err("Invalid RND.IFD value in cryptogram EIC".into());
	}

	// 5) The IFD and the IC derive session keys KSEnc and KSMAC using the key
	// derivation mechanism described in Sections 9.7.1. and 9.7.4
	// with (K.IC xor K.IFD) as shared secret
	let mut k_ic_xor_k_ifd = vec![0; k_ifd.len()];
	for (i, (a, b)) in k_ifd.iter().zip(k_ic.iter()).enumerate() {
		k_ic_xor_k_ifd[i] = *a ^ *b;
	}

	let ks_enc = derive_key(&k_ic_xor_k_ifd, 1);

	let ks_mac = derive_key(&k_ic_xor_k_ifd, 2);

	let mut ssc = Vec::with_capacity(8);
	ssc.extend_from_slice(&get_challenge_res.data[4..8]);
	ssc.extend_from_slice(&rnd_ifd[4..8]);
	let ssc = u64::from_be_bytes([ssc[0], ssc[1], ssc[2], ssc[3], ssc[4], ssc[5], ssc[6], ssc[7]]);

	Ok(SessionKeys { ks_enc, ks_mac, ssc })
}

const APDU_INITIAL_SELECT: ApduCommand = ApduCommand { cla: 0x00, ins: 0xA4, p1: 0x04, p2: 0x0C, data: &[0xa0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01], rx_len: 0 };
const APDU_GET_CHALLENGE: ApduCommand = ApduCommand { cla: 0x00, ins: 0x84, p1: 0x00, p2: 0x00, data: &[], rx_len: 8 };
pub fn apdu_external_authenticate(data: &[u8]) -> ApduCommand {
	ApduCommand { cla: 0x00, ins: 0x82, p1: 0x00, p2: 0x00, data, rx_len: 40 }
}