use super::{FILL_CHAR, MrzFormat};
use super::iter::{CompositeDataChars, DocumentNumberChars, DocumentNumberCharsWithCheckDigit, DataWithCheckDigit, MrzInformation};
use super::error::Error;
use super::check_digit::sum;
use crate::crypto::derive_key;

use chrono::NaiveDate;
use sha1::{Sha1, Digest};

pub trait MrzData<'a>: ToString + TryFrom<&'a str, Error = Error> {
	fn format(&self) -> MrzFormat;
	fn str_len(&self) -> usize;
	fn document_code(&self) -> &str;
	fn document_code_is_valid(&self) -> Result<(), Error>;
	fn issuer(&self) -> &str;
	fn document_number(&self) -> &str;
	fn document_number_check_digit(&self) -> &str;
	fn date_of_birth(&self) -> &str;
	fn date_of_birth_check_digit(&self) -> &str;
	fn date_of_expiry(&self) -> &str;
	fn date_of_expiry_check_digit(&self) -> &str;
	fn name(&self) -> &str;
	fn sex(&self) -> &str;
	fn nationality(&self) -> &str;
	fn optional_data_1(&self) -> &str;
	fn optional_data_1_check_digit(&self) -> Option<&str>;
	fn optional_data_2(&self) -> Option<&str>;
	fn composite_check_digit(&self) -> &str;
	fn composite_data(&self) -> CompositeDataChars;

	fn derive_seed_key(&self) -> Vec<u8> {
		let mut hasher = Sha1::new();
		hasher.update(self.document_number());

		let mut long_doc_num = false;
		let opt = self.optional_data_1();
		let check_digit = self.document_number_check_digit();
		if check_digit.len() == 0 || check_digit.chars().next() == Some(FILL_CHAR) {
			if let Some(end) = opt.chars().position(|c| c == FILL_CHAR) {
				if end >= 2 {
					hasher.update(&opt[..end]);
					long_doc_num = true;
				}
			}
		}
		if !long_doc_num {
			hasher.update(check_digit);
		}

		hasher.update(self.date_of_birth());
		hasher.update(self.date_of_birth_check_digit());
		hasher.update(self.date_of_expiry());
		hasher.update(self.date_of_expiry_check_digit());

		let mut key_seed = hasher.finalize().to_vec();
		key_seed.resize(16, 0);
		key_seed
	}

	fn derive_key(&self, counter: u32) -> Vec<u8> {
		if counter == 0 {
			return self.derive_seed_key()
		}
		derive_key(&self.derive_seed_key(), counter)
	}

	fn names(&self) -> Vec<Vec<&str>> {
		self.name()
			.trim_end_matches(FILL_CHAR)
			.split("<<")
			.map(|names| names.split(FILL_CHAR).collect())
			.collect()
	}

	fn names_owned(&self) -> Vec<Vec<String>> {
		self.name()
			.trim_end_matches(FILL_CHAR)
			.split("<<")
			.map(|names| names.split(FILL_CHAR).map(|name| name.to_owned()).collect())
			.collect()
	}

	fn full_document_number_check_digit(&self) -> &str {
		let check_digit = self.document_number_check_digit();
		let opt = self.optional_data_1();
		if check_digit == "<" {
			if let Some(end) = opt.chars().position(|c| c == FILL_CHAR) {
				if end >= 2 {
					return &opt[end-1..];
				}
			}
		}
		check_digit
	}

	fn full_document_number(&self) -> DocumentNumberChars {
		let doc_num = self.document_number();
		let check_digit = self.document_number_check_digit();
		let opt = self.optional_data_1();
		if check_digit == "<" {
			if let Some(end) = opt.chars().position(|c| c == FILL_CHAR) {
				if end >= 2 {
					return DocumentNumberChars::Long(doc_num.chars().chain(opt[..end-1].chars()));
				}
			}
		}
		DocumentNumberChars::Short(doc_num.chars())
	}

	fn full_document_number_with_check_digit(&self) -> DocumentNumberCharsWithCheckDigit {
		self.full_document_number()
			.chain(self.full_document_number_check_digit().chars())
	}

	fn date_of_birth_with_check_digit(&self) -> DataWithCheckDigit {
		self.date_of_birth().chars()
			.chain(self.date_of_birth_check_digit().chars())
	}

	fn date_of_expiry_with_check_digit(&self) -> DataWithCheckDigit {
		self.date_of_expiry().chars()
			.chain(self.date_of_expiry_check_digit().chars())
	}

	fn mrz_information(&self) -> MrzInformation {
		self.full_document_number_with_check_digit()
			.chain(self.date_of_birth_with_check_digit())
			.chain(self.date_of_expiry_with_check_digit())
	}

	fn is_valid(&self) -> Result<(), Error> {
		if self.document_number_check_digit() == "<" {
			if let Some(end) = self.optional_data_1().chars().position(|c| c == FILL_CHAR) {
				if end < 2 {
					return Err(Error::InvalidDocumentNumber);
				}
			} else {
				return Err(Error::InvalidDocumentNumber);
			}
		}
		if Ok(sum(self.full_document_number())) != self.full_document_number_check_digit().parse() {
			return Err(Error::InvalidChecksum);
		}
		if Ok(sum(self.date_of_birth().chars())) != self.date_of_birth_check_digit().parse() {
			return Err(Error::InvalidChecksum);
		}
		NaiveDate::parse_from_str(self.date_of_birth(), "%y%m%d")?;
		if Ok(sum(self.date_of_expiry().chars())) != self.date_of_expiry_check_digit().parse() {
			return Err(Error::InvalidChecksum);
		}
		NaiveDate::parse_from_str(self.date_of_expiry(), "%y%m%d")?;
		if Ok(sum(self.composite_data())) != self.composite_check_digit().parse() {
			return Err(Error::InvalidChecksum);
		}
		if let Some(optional_data_1_check_digit) = self.optional_data_1_check_digit() {
			if Ok(sum(self.optional_data_1().chars())) != optional_data_1_check_digit.parse() {
				return Err(Error::InvalidChecksum);
			}
		}
		self.document_code_is_valid()
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrzDataTd1<'a> {
	// Line 1
	document_code: &'a str,
	issuer: &'a str,
	document_number: &'a str,
	document_number_check_digit: &'a str,
	optional_data_1: &'a str,
	// Line 2
	date_of_birth: &'a str,
	date_of_birth_check_digit: &'a str,
	sex: &'a str,
	date_of_expiry: &'a str,
	date_of_expiry_check_digit: &'a str,
	nationality: &'a str,
	optional_data_2: &'a str,
	composite_check_digit: &'a str,
	// Line 3
	name: &'a str,
}

impl<'a> MrzDataTd1<'a> {
	pub fn format() -> MrzFormat {
		MrzFormat::Td1
	}
	pub fn str_len() -> usize {
		90
	}
}

impl<'a> MrzData<'a> for MrzDataTd1<'a> {
	fn format(&self) -> MrzFormat {
		MrzDataTd1::format()
	}
	fn str_len(&self) -> usize {
		MrzDataTd1::str_len()
	}
	fn document_code(&self) -> &str {
		self.document_code
	}
	fn document_code_is_valid(&self) -> Result<(), Error> {
		match self.document_code.chars().next() {
			Some('I') | Some('A') | Some('C') => Ok(()),
			_ => Err(Error::InvalidDocumentCode),
		}
	}
	fn issuer(&self) -> &str {
		self.issuer
	}
	fn document_number(&self) -> &str {
		self.document_number
	}
	fn document_number_check_digit(&self) -> &str {
		self.document_number_check_digit
	}
	fn date_of_birth(&self) -> &str {
		self.date_of_birth
	}
	fn date_of_birth_check_digit(&self) -> &str {
		self.date_of_birth_check_digit
	}
	fn date_of_expiry(&self) -> &str {
		self.date_of_expiry
	}
	fn date_of_expiry_check_digit(&self) -> &str {
		self.date_of_expiry_check_digit
	}
	fn name(&self) -> &str {
		self.name
	}
	fn sex(&self) -> &str {
		self.sex
	}
	fn nationality(&self) -> &str {
		self.nationality
	}
	fn optional_data_1(&self) -> &str {
		self.optional_data_1
	}
	fn optional_data_1_check_digit(&self) -> Option<&str> {
		None
	}
	fn optional_data_2(&self) -> Option<&str> {
		Some(self.optional_data_2)
	}
	fn composite_check_digit(&self) -> &str {
		self.composite_check_digit
	}
	fn composite_data(&self) -> CompositeDataChars {
		CompositeDataChars::Td1(
			self.document_number.chars()
				.chain(self.document_number_check_digit.chars())
				.chain(self.optional_data_1.chars())
				.chain(self.date_of_birth.chars())
				.chain(self.date_of_birth_check_digit.chars())
				.chain(self.date_of_expiry.chars())
				.chain(self.date_of_expiry_check_digit.chars())
				.chain(self.optional_data_2.chars())
		)
	}
}

impl<'a> ToString for MrzDataTd1<'a> {
	fn to_string(&self) -> String {
		let mut output = String::with_capacity(90);
		output.push_str(&self.document_code[0..2]);
		output.push_str(&self.issuer[0..3]);
		output.push_str(&self.document_number[0..9]);
		output.push_str(&self.document_number_check_digit[0..1]);
		output.push_str(&self.optional_data_1[0..15]);
		output.push_str(&self.date_of_birth[0..6]);
		output.push_str(&self.date_of_birth_check_digit[0..1]);
		output.push_str(&self.sex[0..1]);
		output.push_str(&self.date_of_expiry[0..6]);
		output.push_str(&self.date_of_expiry_check_digit[0..1]);
		output.push_str(&self.nationality[0..3]);
		output.push_str(&self.optional_data_2[0..11]);
		output.push_str(&self.composite_check_digit[0..1]);
		output.push_str(&self.name[0..30]);
		output
	}
}

impl<'a> TryFrom<&'a str> for MrzDataTd1<'a> {
	type Error = Error;
	fn try_from(input: &'a str) -> Result<Self, Self::Error> {
		if input.len() != MrzDataTd1::str_len() {
			return Err(Error::InvalidLength);
		}
		Ok(Self {
			document_code: &input[0..2],
			issuer: &input[2..5],
			document_number: &input[5..14],
			document_number_check_digit: &input[14..15],
			optional_data_1: &input[15..30],
			date_of_birth: &input[30..36],
			date_of_birth_check_digit: &input[36..37],
			sex: &input[37..38],
			date_of_expiry: &input[38..44],
			date_of_expiry_check_digit: &input[44..45],
			nationality: &input[45..48],
			optional_data_2: &input[48..59],
			composite_check_digit: &input[59..60],
			name: &input[60..90],
		})
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrzDataTd2<'a> {
	// Line 1
	document_code: &'a str,
	issuer: &'a str,
	name: &'a str,
	// Line 2
	document_number: &'a str,
	document_number_check_digit: &'a str,
	nationality: &'a str,
	date_of_birth: &'a str,
	date_of_birth_check_digit: &'a str,
	sex: &'a str,
	date_of_expiry: &'a str,
	date_of_expiry_check_digit: &'a str,
	optional_data_1: &'a str,
	composite_check_digit: &'a str,
}

impl<'a> MrzDataTd2<'a> {
	pub fn format() -> MrzFormat {
		MrzFormat::Td2
	}
	pub fn str_len() -> usize {
		72
	}
}

impl<'a> MrzData<'a> for MrzDataTd2<'a> {
	fn format(&self) -> MrzFormat {
		MrzDataTd2::format()
	}
	fn str_len(&self) -> usize {
		MrzDataTd2::str_len()
	}
	fn document_code(&self) -> &str {
		self.document_code
	}
	fn document_code_is_valid(&self) -> Result<(), Error> {
		match self.document_code.chars().next() {
			Some('I') | Some('P') | Some('A') | Some('C') => Ok(()),
			_ => Err(Error::InvalidDocumentCode),
		}
	}
	fn issuer(&self) -> &str {
		self.issuer
	}
	fn document_number(&self) -> &str {
		self.document_number
	}
	fn document_number_check_digit(&self) -> &str {
		self.document_number_check_digit
	}
	fn date_of_birth(&self) -> &str {
		self.date_of_birth
	}
	fn date_of_birth_check_digit(&self) -> &str {
		self.date_of_birth_check_digit
	}
	fn date_of_expiry(&self) -> &str {
		self.date_of_expiry
	}
	fn date_of_expiry_check_digit(&self) -> &str {
		self.date_of_expiry_check_digit
	}
	fn name(&self) -> &str {
		self.name
	}
	fn sex(&self) -> &str {
		self.sex
	}
	fn nationality(&self) -> &str {
		self.nationality
	}
	fn optional_data_1(&self) -> &str {
		self.optional_data_1
	}
	fn optional_data_1_check_digit(&self) -> Option<&str> {
		None
	}
	fn optional_data_2(&self) -> Option<&str> {
		None
	}
	fn composite_check_digit(&self) -> &str {
		self.composite_check_digit
	}
	fn composite_data(&self) -> CompositeDataChars {
		CompositeDataChars::Td2(
			self.document_number.chars()
				.chain(self.document_number_check_digit.chars())
				.chain(self.date_of_birth.chars())
				.chain(self.date_of_birth_check_digit.chars())
				.chain(self.date_of_expiry.chars())
				.chain(self.date_of_expiry_check_digit.chars())
				.chain(self.optional_data_1.chars())
		)
	}
}

impl<'a> ToString for MrzDataTd2<'a> {
	fn to_string(&self) -> String {
		let mut output = String::with_capacity(72);
		output.push_str(&self.document_code[0..2]);
		output.push_str(&self.issuer[0..3]);
		output.push_str(&self.name[0..31]);
		output.push_str(&self.document_number[0..9]);
		output.push_str(&self.document_number_check_digit[0..1]);
		output.push_str(&self.nationality[0..3]);
		output.push_str(&self.date_of_birth[0..6]);
		output.push_str(&self.date_of_birth_check_digit[0..1]);
		output.push_str(&self.sex[0..1]);
		output.push_str(&self.date_of_expiry[0..6]);
		output.push_str(&self.date_of_expiry_check_digit[0..1]);
		output.push_str(&self.optional_data_1[0..7]);
		output.push_str(&self.composite_check_digit[0..1]);
		output
	}
}

impl<'a> TryFrom<&'a str> for MrzDataTd2<'a> {
	type Error = Error;
	fn try_from(input: &'a str) -> Result<Self, Self::Error> {
		if input.len() != MrzDataTd2::str_len() {
			return Err(Error::InvalidLength);
		}
		Ok(Self {
			document_code: &input[0..2],
			issuer: &input[2..5],
			name: &input[5..36],
			document_number: &input[36..45],
			document_number_check_digit: &input[45..46],
			nationality: &input[46..49],
			date_of_birth: &input[49..55],
			date_of_birth_check_digit: &input[55..56],
			sex: &input[56..57],
			date_of_expiry: &input[57..63],
			date_of_expiry_check_digit: &input[63..64],
			optional_data_1: &input[64..71],
			composite_check_digit: &input[71..72],
		})
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrzDataTd3<'a> {
	// Line 1
	document_code: &'a str,
	issuer: &'a str,
	name: &'a str,
	// Line 2
	document_number: &'a str,
	document_number_check_digit: &'a str,
	nationality: &'a str,
	date_of_birth: &'a str,
	date_of_birth_check_digit: &'a str,
	sex: &'a str,
	date_of_expiry: &'a str,
	date_of_expiry_check_digit: &'a str,
	optional_data_1: &'a str,
	optional_data_1_check_digit: &'a str,
	composite_check_digit: &'a str,
}

impl<'a> MrzDataTd3<'a> {
	pub fn format() -> MrzFormat {
		MrzFormat::Td3
	}
	pub fn str_len() -> usize {
		88
	}
}

impl<'a> MrzData<'a> for MrzDataTd3<'a> {
	fn format(&self) -> MrzFormat {
		MrzDataTd3::format()
	}
	fn str_len(&self) -> usize {
		MrzDataTd3::str_len()
	}
	fn document_code(&self) -> &str {
		self.document_code
	}
	fn document_code_is_valid(&self) -> Result<(), Error> {
		match self.document_code.chars().next() {
			Some('P') => Ok(()),
			_ => Err(Error::InvalidDocumentCode),
		}
	}
	fn issuer(&self) -> &str {
		self.issuer
	}
	fn document_number(&self) -> &str {
		self.document_number
	}
	fn document_number_check_digit(&self) -> &str {
		self.document_number_check_digit
	}
	fn date_of_birth(&self) -> &str {
		self.date_of_birth
	}
	fn date_of_birth_check_digit(&self) -> &str {
		self.date_of_birth_check_digit
	}
	fn date_of_expiry(&self) -> &str {
		self.date_of_expiry
	}
	fn date_of_expiry_check_digit(&self) -> &str {
		self.date_of_expiry_check_digit
	}
	fn name(&self) -> &str {
		self.name
	}
	fn sex(&self) -> &str {
		self.sex
	}
	fn nationality(&self) -> &str {
		self.nationality
	}
	fn optional_data_1(&self) -> &str {
		self.optional_data_1
	}
	fn optional_data_1_check_digit(&self) -> Option<&str> {
		Some(self.optional_data_1_check_digit)
	}
	fn optional_data_2(&self) -> Option<&str> {
		None
	}
	fn composite_check_digit(&self) -> &str {
		self.composite_check_digit
	}
	fn composite_data(&self) -> CompositeDataChars {
		CompositeDataChars::Td3(
			self.document_number.chars()
				.chain(self.document_number_check_digit.chars())
				.chain(self.date_of_birth.chars())
				.chain(self.date_of_birth_check_digit.chars())
				.chain(self.date_of_expiry.chars())
				.chain(self.date_of_expiry_check_digit.chars())
				.chain(self.optional_data_1.chars())
				.chain(self.optional_data_1_check_digit.chars())
		)
	}
}

impl<'a> ToString for MrzDataTd3<'a> {
	fn to_string(&self) -> String {
		let mut output = String::with_capacity(88);
		output.push_str(&self.document_code[0..2]);
		output.push_str(&self.issuer[0..3]);
		output.push_str(&self.name[0..39]);
		output.push_str(&self.document_number[0..9]);
		output.push_str(&self.document_number_check_digit[0..1]);
		output.push_str(&self.nationality[0..3]);
		output.push_str(&self.date_of_birth[0..6]);
		output.push_str(&self.date_of_birth_check_digit[0..1]);
		output.push_str(&self.sex[0..1]);
		output.push_str(&self.date_of_expiry[0..6]);
		output.push_str(&self.date_of_expiry_check_digit[0..1]);
		output.push_str(&self.optional_data_1[0..14]);
		output.push_str(&self.optional_data_1_check_digit[0..1]);
		output.push_str(&self.composite_check_digit[0..1]);
		output
	}
}

impl<'a> TryFrom<&'a str> for MrzDataTd3<'a> {
	type Error = Error;
	fn try_from(input: &'a str) -> Result<Self, Self::Error> {
		if input.len() != MrzDataTd3::str_len() {
			return Err(Error::InvalidLength);
		}
		Ok(Self {
			document_code: &input[0..2],
			issuer: &input[2..5],
			name: &input[5..44],
			document_number: &input[44..53],
			document_number_check_digit: &input[53..54],
			nationality: &input[54..57],
			date_of_birth: &input[57..63],
			date_of_birth_check_digit: &input[63..64],
			sex: &input[64..65],
			date_of_expiry: &input[65..71],
			date_of_expiry_check_digit: &input[71..72],
			optional_data_1: &input[72..86],
			optional_data_1_check_digit: &input[86..87],
			composite_check_digit: &input[87..88],
		})
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mrz<'a> {
	Td1(MrzDataTd1<'a>),
	Td2(MrzDataTd2<'a>),
	Td3(MrzDataTd3<'a>),
}

impl<'a> MrzData<'a> for Mrz<'a> {
	fn format(&self) -> MrzFormat {
		match self {
			Self::Td1(data) => data.format(),
			Self::Td2(data) => data.format(),
			Self::Td3(data) => data.format(),
		}
	}
	fn str_len(&self) -> usize {
		match self {
			Self::Td1(data) => data.str_len(),
			Self::Td2(data) => data.str_len(),
			Self::Td3(data) => data.str_len(),
		}
	}
	fn document_code(&self) -> &str {
		match self {
			Self::Td1(data) => data.document_code(),
			Self::Td2(data) => data.document_code(),
			Self::Td3(data) => data.document_code(),
		}
	}
	fn document_code_is_valid(&self) -> Result<(), Error> {
		match self {
			Self::Td1(data) => data.document_code_is_valid(),
			Self::Td2(data) => data.document_code_is_valid(),
			Self::Td3(data) => data.document_code_is_valid(),
		}
	}
	fn issuer(&self) -> &str {
		match self {
			Self::Td1(data) => data.issuer(),
			Self::Td2(data) => data.issuer(),
			Self::Td3(data) => data.issuer(),
		}
	}
	fn document_number(&self) -> &str {
		match self {
			Self::Td1(data) => data.document_number(),
			Self::Td2(data) => data.document_number(),
			Self::Td3(data) => data.document_number(),
		}
	}
	fn document_number_check_digit(&self) -> &str {
		match self {
			Self::Td1(data) => data.document_number_check_digit(),
			Self::Td2(data) => data.document_number_check_digit(),
			Self::Td3(data) => data.document_number_check_digit(),
		}
	}
	fn date_of_birth(&self) -> &str {
		match self {
			Self::Td1(data) => data.date_of_birth(),
			Self::Td2(data) => data.date_of_birth(),
			Self::Td3(data) => data.date_of_birth(),
		}
	}
	fn date_of_birth_check_digit(&self) -> &str {
		match self {
			Self::Td1(data) => data.date_of_birth_check_digit(),
			Self::Td2(data) => data.date_of_birth_check_digit(),
			Self::Td3(data) => data.date_of_birth_check_digit(),
		}
	}
	fn date_of_expiry(&self) -> &str {
		match self {
			Self::Td1(data) => data.date_of_expiry(),
			Self::Td2(data) => data.date_of_expiry(),
			Self::Td3(data) => data.date_of_expiry(),
		}
	}
	fn date_of_expiry_check_digit(&self) -> &str {
		match self {
			Self::Td1(data) => data.date_of_expiry_check_digit(),
			Self::Td2(data) => data.date_of_expiry_check_digit(),
			Self::Td3(data) => data.date_of_expiry_check_digit(),
		}
	}
	fn name(&self) -> &str {
		match self {
			Self::Td1(data) => data.name(),
			Self::Td2(data) => data.name(),
			Self::Td3(data) => data.name(),
		}
	}
	fn sex(&self) -> &str {
		match self {
			Self::Td1(data) => data.sex(),
			Self::Td2(data) => data.sex(),
			Self::Td3(data) => data.sex(),
		}
	}
	fn nationality(&self) -> &str {
		match self {
			Self::Td1(data) => data.nationality(),
			Self::Td2(data) => data.nationality(),
			Self::Td3(data) => data.nationality(),
		}
	}
	fn optional_data_1(&self) -> &str {
		match self {
			Self::Td1(data) => data.optional_data_1(),
			Self::Td2(data) => data.optional_data_1(),
			Self::Td3(data) => data.optional_data_1(),
		}
	}
	fn optional_data_1_check_digit(&self) -> Option<&str> {
		match self {
			Self::Td1(data) => data.optional_data_1_check_digit(),
			Self::Td2(data) => data.optional_data_1_check_digit(),
			Self::Td3(data) => data.optional_data_1_check_digit(),
		}
	}
	fn optional_data_2(&self) -> Option<&str> {
		match self {
			Self::Td1(data) => data.optional_data_2(),
			Self::Td2(data) => data.optional_data_2(),
			Self::Td3(data) => data.optional_data_2(),
		}
	}
	fn composite_check_digit(&self) -> &str {
		match self {
			Self::Td1(data) => data.composite_check_digit(),
			Self::Td2(data) => data.composite_check_digit(),
			Self::Td3(data) => data.composite_check_digit(),
		}
	}
	fn composite_data(&self) -> CompositeDataChars {
		match self {
			Self::Td1(data) => data.composite_data(),
			Self::Td2(data) => data.composite_data(),
			Self::Td3(data) => data.composite_data(),
		}
	}
}

impl<'a> ToString for Mrz<'a> {
	fn to_string(&self) -> String {
		match self {
			Self::Td1(data) => data.to_string(),
			Self::Td2(data) => data.to_string(),
			Self::Td3(data) => data.to_string(),
		}
	}
}

impl<'a> TryFrom<&'a str> for Mrz<'a> {
	type Error = Error;
	fn try_from(value: &'a str) -> Result<Self, Self::Error> {
		MrzDataTd1::try_from(value).map(|data| Mrz::Td1(data))
			.or_else(|e| if e == Error::InvalidLength {
				MrzDataTd2::try_from(value).map(|data| Mrz::Td2(data))
			} else {
				Err(e)
			})
			.or_else(|e| if e == Error::InvalidLength {
				MrzDataTd3::try_from(value).map(|data| Mrz::Td3(data))
			} else {
				Err(e)
			})
	}
}