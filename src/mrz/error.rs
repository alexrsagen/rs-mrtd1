#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
	InvalidLength,
	InvalidChecksum,
	InvalidDocumentCode,
	InvalidDocumentNumber,
	InvalidDate(chrono::format::ParseError),
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::InvalidLength => write!(f, "Invalid data length"),
			Self::InvalidChecksum => write!(f, "Failed checksum validation"),
			Self::InvalidDocumentCode => write!(f, "Document code is invalid for MRZ type"),
			Self::InvalidDocumentNumber => write!(f, "Document number check digit is empty, long document number in optional data is invalid"),
			Self::InvalidDate(e) => write!(f, "Invalid date: {}", e)
		}
	}
}

impl std::error::Error for Error {}

impl From<chrono::format::ParseError> for Error {
	fn from(e: chrono::format::ParseError) -> Self {
		Self::InvalidDate(e)
	}
}