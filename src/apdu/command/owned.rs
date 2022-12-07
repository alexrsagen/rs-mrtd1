use super::borrowed::ApduCommand as BorrowedApduCommand;

#[derive(Debug, PartialEq, Eq)]
pub struct ApduCommand {
	pub cla: u8,
	pub ins: u8,
	pub p1: u8,
	pub p2: u8,
	pub data: Vec<u8>,
	pub rx_len: usize,
}

impl ApduCommand {
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
		if self.rx_len < 256 {
			buf.extend_from_slice(&[(self.rx_len & 0xFF) as u8]);
		} else if self.rx_len == 256 {
			buf.extend_from_slice(&[0x00]);
		} else if self.rx_len == 65536 && lc_extended {
			buf.extend_from_slice(&[0x00, 0x00]);
		} else if self.rx_len < 65536 && lc_extended {
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
}

impl<'a> From<&'a ApduCommand> for BorrowedApduCommand<'a> {
	fn from(apdu: &'a ApduCommand) -> Self {
		Self { cla: apdu.cla, ins: apdu.ins, p1: apdu.p1, p2: apdu.p2, data: &apdu.data, rx_len: apdu.rx_len }
	}
}