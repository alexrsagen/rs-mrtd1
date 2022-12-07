use std::iter::{repeat, Take, Repeat};

use super::{FILL_CHAR, MrzFormat};
use super::iter::CompositeDataChars;
use super::borrowed::{MrzData, Mrz as BorrowedMrz};
use super::check_digit::sum;
use crate::crypto::derive_key;

use chrono::NaiveDate;

fn fill(count: usize) -> Take<Repeat<char>> {
	repeat(FILL_CHAR).take(count)
}

fn push_data(s: &mut String, value: &str, len: usize) {
	s.push_str(&value[0..value.len().min(len)]);
	if value.len() < len {
		s.extend(fill(len - value.len()));
	}
}

fn push_opt_data(s: &mut String, value: Option<&str>, len: usize) {
	if let Some(value) = value {
		s.push_str(&value[0..value.len().min(len)]);
	}
	let value_len = value.map(|v| v.len()).unwrap_or_default();
	if value_len < len {
		s.extend(fill(len - value_len));
	}
}

fn push_names(s: &mut String, names: &Vec<Vec<String>>, len: usize) {
	let mut n = 0;
	let mut segments = names.iter().peekable();
	while let Some(segment) = segments.next() {
		let mut parts = segment.iter().peekable();
		while let Some(part) = parts.next() {
			s.push_str(part);
			n += part.len();
			if parts.peek().is_some() {
				s.push(FILL_CHAR);
				n += 1;
			}
		}
		if segments.peek().is_some() {
			s.push(FILL_CHAR);
			s.push(FILL_CHAR);
			n += 2;
		}
	}
	if n < len {
		s.extend(fill(len - n));
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sex {
	Male,
	Female,
	Unspecified,
}

impl Default for Sex {
	fn default() -> Self { Self::Unspecified }
}

impl std::str::FromStr for Sex {
	type Err = std::convert::Infallible;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"M" => Ok(Self::Male),
			"F" => Ok(Self::Female),
			_ => Ok(Default::default()),
		}
	}
}

impl ToString for Sex {
	fn to_string(&self) -> String {
		match self {
			Self::Male => String::from("M"),
			Self::Female => String::from("F"),
			Self::Unspecified => String::from(FILL_CHAR),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mrz {
	pub format: MrzFormat,
	pub document_code: String,
	pub document_number: String,
	pub issuer: String,
	pub names: Vec<Vec<String>>,
	pub date_of_birth: NaiveDate,
	pub date_of_expiry: NaiveDate,
	pub sex: Sex,
	pub nationality: String,
	pub optional_data_1: Option<String>,
	pub optional_data_2: Option<String>,
	pub key_seed: Vec<u8>,
    pub key_enc: Vec<u8>,
    pub key_mac: Vec<u8>,
}

impl<'a> TryFrom<BorrowedMrz<'a>> for Mrz {
	type Error = super::error::Error;
	fn try_from(mrz: BorrowedMrz) -> Result<Self, Self::Error> {
		let optional_data_1 = mrz.optional_data_1().trim_end_matches(FILL_CHAR).to_owned();
		let optional_data_1 = if optional_data_1.len() > 0 { Some(optional_data_1) } else { None };
        let key_seed = mrz.derive_seed_key();
        let key_enc = derive_key(&key_seed, 1);
        let key_mac = derive_key(&key_seed, 2);
		Ok(Self{
			format: mrz.format(),
			document_code: mrz.document_code().trim_end_matches(FILL_CHAR).to_owned(),
			document_number: String::from_iter(mrz.full_document_number()).trim_end_matches(FILL_CHAR).to_owned(),
			issuer: mrz.issuer().trim_end_matches(FILL_CHAR).to_owned(),
			names: mrz.names_owned(),
			date_of_birth: NaiveDate::parse_from_str(mrz.date_of_birth(), "%y%m%d")?,
			date_of_expiry: NaiveDate::parse_from_str(mrz.date_of_expiry(), "%y%m%d")?,
			sex: mrz.sex().parse().unwrap_or_default(),
			nationality: mrz.nationality().trim_end_matches(FILL_CHAR).to_owned(),
			optional_data_1,
			optional_data_2: mrz.optional_data_2().map(|s| s.trim_end_matches(FILL_CHAR).to_owned()),
			key_seed,
            key_enc,
            key_mac,
		})
	}
}

impl<'a> ToString for Mrz {
	fn to_string(&self) -> String {
		match self.format {
			MrzFormat::Td1 => {
				let mut output = String::with_capacity(90);
				push_data(&mut output, &self.document_code, 2);
				push_data(&mut output, &self.issuer, 3);
				push_data(&mut output, &self.document_number, 9);
				output.push_str(sum((&output[output.len()-9..]).chars()).to_string().as_str());
				push_opt_data(&mut output, self.optional_data_1.as_deref(), 15);
				push_data(&mut output, self.date_of_birth.format("%y%m%d").to_string().as_str(), 6);
				output.push_str(sum((&output[output.len()-6..]).chars()).to_string().as_str());
				push_data(&mut output, self.sex.to_string().as_str(), 1);
				push_data(&mut output, self.date_of_expiry.format("%y%m%d").to_string().as_str(), 6);
				output.push_str(sum((&output[output.len()-6..]).chars()).to_string().as_str());
				push_data(&mut output, &self.nationality, 3);
				push_opt_data(&mut output, self.optional_data_2.as_deref(), 11);
				output.push_str(sum(CompositeDataChars::Td1((&output[5..14]).chars()
					.chain((&output[14..15]).chars())
					.chain((&output[15..30]).chars())
					.chain((&output[30..36]).chars())
					.chain((&output[36..37]).chars())
					.chain((&output[38..44]).chars())
					.chain((&output[44..45]).chars())
					.chain((&output[48..59]).chars()))).to_string().as_str());
				push_names(&mut output, &self.names, 30);
				output
			}
			MrzFormat::Td2 => {
				let mut output = String::with_capacity(72);
				push_data(&mut output, &self.document_code, 2);
				push_data(&mut output, &self.issuer, 3);
				push_names(&mut output, &self.names, 31);
				push_data(&mut output, &self.document_number, 9);
				output.push_str(sum((&output[output.len()-9..]).chars()).to_string().as_str());
				push_data(&mut output, &self.nationality, 3);
				push_data(&mut output, self.date_of_birth.format("%y%m%d").to_string().as_str(), 6);
				output.push_str(sum((&output[output.len()-6..]).chars()).to_string().as_str());
				push_data(&mut output, self.sex.to_string().as_str(), 1);
				push_data(&mut output, self.date_of_expiry.format("%y%m%d").to_string().as_str(), 6);
				output.push_str(sum((&output[output.len()-6..]).chars()).to_string().as_str());
				push_opt_data(&mut output, self.optional_data_1.as_deref(), 7);
				output.push_str(sum(CompositeDataChars::Td2((&output[36..45]).chars()
					.chain((&output[45..46]).chars())
					.chain((&output[49..55]).chars())
					.chain((&output[55..56]).chars())
					.chain((&output[57..63]).chars())
					.chain((&output[63..64]).chars())
					.chain((&output[64..71]).chars()))).to_string().as_str());
				output
			}
			MrzFormat::Td3 => {
				let mut output = String::with_capacity(88);
				push_data(&mut output, &self.document_code, 2);
				push_data(&mut output, &self.issuer, 3);
				push_names(&mut output, &self.names, 39);
				push_data(&mut output, &self.document_number, 9);
				output.push_str(sum((&output[output.len()-9..]).chars()).to_string().as_str());
				push_data(&mut output, &self.nationality, 3);
				push_data(&mut output, self.date_of_birth.format("%y%m%d").to_string().as_str(), 6);
				output.push_str(sum((&output[output.len()-6..]).chars()).to_string().as_str());
				push_data(&mut output, self.sex.to_string().as_str(), 1);
				push_data(&mut output, self.date_of_expiry.format("%y%m%d").to_string().as_str(), 6);
				output.push_str(sum((&output[output.len()-6..]).chars()).to_string().as_str());
				push_opt_data(&mut output, self.optional_data_1.as_deref(), 14);
				output.push_str(sum((&output[output.len()-14..]).chars()).to_string().as_str());
				output.push_str(sum(CompositeDataChars::Td3((&output[44..53]).chars()
					.chain((&output[53..54]).chars())
					.chain((&output[57..63]).chars())
					.chain((&output[63..64]).chars())
					.chain((&output[65..71]).chars())
					.chain((&output[71..72]).chars())
					.chain((&output[72..86]).chars())
					.chain((&output[86..87]).chars()))).to_string().as_str());
				output
			}
		}
	}
}