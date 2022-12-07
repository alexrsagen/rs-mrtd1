use crate::error::BoxResult;
use super::padding::pad;
use block_padding::ZeroPadding;
use cbc::cipher::{KeyIvInit, BlockEncryptMut, BlockDecryptMut};

pub type DesCbcEnc = cbc::Encryptor<des::Des>;
pub type DesCbcDec = cbc::Decryptor<des::Des>;

pub const ZERO_IV: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

pub fn encrypt(input: &[u8], key: &[u8]) -> BoxResult<Vec<u8>> {
	let mut output = input.to_vec();
	DesCbcEnc::new(key.into(), &ZERO_IV.into())
		.encrypt_padded_mut::<ZeroPadding>(&mut output, input.len()).map_err(|e| e.to_string())?;
	Ok(output)
}

pub fn decrypt(input: &[u8], key: &[u8]) -> BoxResult<Vec<u8>> {
	let mut output = input.to_vec();
	DesCbcDec::new(key.into(), &ZERO_IV.into())
		.decrypt_padded_mut::<ZeroPadding>(&mut output).map_err(|e| e.to_string())?;
	Ok(output)
}

/// ISO/IEC 9797-1:2011 MAC Algorithm 3
pub fn mac(data: &[u8], key: &[u8]) -> BoxResult<Vec<u8>> {
	let padded_data = pad(data);
	let (k1, k2) = key.split_at(8);
	let d: Vec<Vec<u8>> = padded_data.chunks_exact(8).map(|chunk| chunk.to_vec()).collect();
	let mut h = vec![vec![0; 8]; d.len()];

	// Initial transformation 1
	h[0] = encrypt(&d[0], k1)?;

	// Iteration
	for i in 1..d.len() {
		for j in 0..8 {
			h[i][j] = d[i][j] ^ h[i-1][j];
		}
		h[i] = encrypt(&h[i], k1)?;
	}

	// Output transformation 3
	let g = encrypt(&decrypt(&h[d.len()-1], k2)?, k1)?;
	Ok(g)
}