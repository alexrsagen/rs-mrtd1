pub mod borrowed;
pub mod check_digit;
pub mod error;
pub mod iter;
pub mod owned;

pub(crate) const FILL_CHAR: char = '<';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MrzFormat {
	Td1,
	Td2,
	Td3,
}

pub fn normalize_mrz_string(input: &str) -> String {
	let mut normalized = input.replace(|c: char| !c.is_ascii_alphanumeric() && c != FILL_CHAR, "");
	normalized.make_ascii_uppercase();
	normalized
}