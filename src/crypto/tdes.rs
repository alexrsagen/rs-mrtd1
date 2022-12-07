use crate::error::BoxResult;
use super::padding::{pad, unpad};
use super::des::ZERO_IV;
use block_padding::ZeroPadding;
use cbc::cipher::{KeyIvInit, BlockEncryptMut, BlockDecryptMut};

pub type TdesEde3CbcEnc = cbc::Encryptor<des::TdesEde3>;
pub type TdesEde3CbcDec = cbc::Decryptor<des::TdesEde3>;

pub fn encrypt(input: &[u8], key: &[u8]) -> BoxResult<Vec<u8>> {
	let mut output = input.to_vec();
	let mut longkey = Vec::with_capacity(24);
	longkey.extend_from_slice(&key[0..16]);
	longkey.extend_from_slice(&key[0..8]);
	TdesEde3CbcEnc::new(longkey.as_slice().into(), &ZERO_IV.into())
		.encrypt_padded_mut::<ZeroPadding>(&mut output, input.len()).map_err(|e| e.to_string())?;
	Ok(output)
}

pub fn decrypt(input: &[u8], key: &[u8]) -> BoxResult<Vec<u8>> {
	let mut output = input.to_vec();
	let mut longkey = Vec::with_capacity(24);
	longkey.extend_from_slice(&key[0..16]);
	longkey.extend_from_slice(&key[0..8]);
	TdesEde3CbcDec::new(longkey.as_slice().into(), &ZERO_IV.into())
		.decrypt_padded_mut::<ZeroPadding>(&mut output).map_err(|e| e.to_string())?;
	Ok(output)
}

pub fn encrypt_pad(input: &[u8], key: &[u8]) -> BoxResult<Vec<u8>> {
	let input_padded = pad(input);
	encrypt(&input_padded, key)
}

pub fn decrypt_unpad(input: &[u8], key: &[u8]) -> BoxResult<Vec<u8>> {
	let decrypted = decrypt(input, key)?;
	unpad(decrypted)
}