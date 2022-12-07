use std::iter::Chain;
use std::str::Chars;

#[derive(Debug, Clone)]
pub enum CompositeDataChars<'a> {
	Td1(Chain<Chain<Chain<Chain<Chain<Chain<Chain<Chars<'a>, Chars<'a>>, Chars<'a>>, Chars<'a>>, Chars<'a>>, Chars<'a>>, Chars<'a>>, Chars<'a>>),
	Td2(Chain<Chain<Chain<Chain<Chain<Chain<Chars<'a>, Chars<'a>>, Chars<'a>>, Chars<'a>>, Chars<'a>>, Chars<'a>>, Chars<'a>>),
	Td3(Chain<Chain<Chain<Chain<Chain<Chain<Chain<Chars<'a>, Chars<'a>>, Chars<'a>>, Chars<'a>>, Chars<'a>>, Chars<'a>>, Chars<'a>>, Chars<'a>>),
}

impl<'a> Iterator for CompositeDataChars<'a> {
	type Item = char;
	fn next(&mut self) -> Option<Self::Item> {
		match self {
			Self::Td1(v) => v.next(),
			Self::Td2(v) => v.next(),
			Self::Td3(v) => v.next(),
		}
	}
}

#[derive(Debug, Clone)]
pub enum DocumentNumberChars<'a> {
	Short(Chars<'a>),
	Long(Chain<Chars<'a>, Chars<'a>>),
}

impl<'a> Iterator for DocumentNumberChars<'a> {
	type Item = char;
	fn next(&mut self) -> Option<Self::Item> {
		match self {
			Self::Short(v) => v.next(),
			Self::Long(v) => v.next(),
		}
	}
}

pub type DocumentNumberCharsWithCheckDigit<'a> = Chain<DocumentNumberChars<'a>, Chars<'a>>;
pub type DataWithCheckDigit<'a> = Chain<Chars<'a>, Chars<'a>>;
pub type MrzInformation<'a> = Chain<Chain<DocumentNumberCharsWithCheckDigit<'a>, DataWithCheckDigit<'a>>, DataWithCheckDigit<'a>>;