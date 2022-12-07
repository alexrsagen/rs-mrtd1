use crate::error::BoxResult;

pub fn pad(input: &[u8]) -> Vec<u8> {
	let new_len = ((input.len()+8)/8)*8;
	let mut output = input.to_vec();
	output.resize(new_len, 0);
	output[input.len()] = 0x80;
	output
}

pub fn unpad(mut input: Vec<u8>) -> BoxResult<Vec<u8>> {
	for (i, c) in input.iter().enumerate().rev() {
		if *c == 0x00 {
			continue
		} else if *c == 0x80 {
			input.resize(i, 0);
			return Ok(input);
		} else {
			return Err(format!("Unexpected data {:?} at position {} of padded data", c, i).into())
		}
	}
	Ok(input)
}