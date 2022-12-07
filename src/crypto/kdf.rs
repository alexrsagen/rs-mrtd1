use sha1::{Sha1, Digest};

pub fn derive_key(key: &[u8], counter: u32) -> Vec<u8> {
	let mut hasher = Sha1::new();
	hasher.update(key);
	hasher.update(counter.to_be_bytes());

	let mut key = hasher.finalize().to_vec();
	key.resize(16, 0);

	for i in 0..key.len() {
		let mut parity = false;
		for j in 0..64usize {
			if key[i] & (0x01usize << j) as u8 == 0x00 {
				parity = !parity;
			}
		}
		if !parity {
			key[i] ^= 0x01;
		}
	}

	key
}