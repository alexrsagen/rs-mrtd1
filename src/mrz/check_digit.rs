use super::FILL_CHAR;

const CHECK_DIGIT_WEIGHT: [char; 3] = [7 as char, 3 as char, 1 as char];

fn char_weight(input: char) -> u8 {
	let input = input.to_ascii_uppercase();
	match input {
		'0' => 0,
		'1' => 1,
		'2' => 2,
		'3' => 3,
		'4' => 4,
		'5' => 5,
		'6' => 6,
		'7' => 7,
		'8' => 8,
		'9' => 9,
		'A' => 10,
		'B' => 11,
		'C' => 12,
		'D' => 13,
		'E' => 14,
		'F' => 15,
		'G' => 16,
		'H' => 17,
		'I' => 18,
		'J' => 19,
		'K' => 20,
		'L' => 21,
		'M' => 22,
		'N' => 23,
		'O' => 24,
		'P' => 25,
		'Q' => 26,
		'R' => 27,
		'S' => 28,
		'T' => 29,
		'U' => 30,
		'V' => 31,
		'W' => 32,
		'X' => 33,
		'Y' => 34,
		'Z' => 35,
		FILL_CHAR => 0,
		_ => 0,
	}
}

pub fn sum<I: Iterator<Item = char>>(data: I) -> u8 {
	let sum: u32 = data
		.zip(CHECK_DIGIT_WEIGHT.iter().cycle())
		.map(|(c, weight)| char_weight(c) as u32 * (*weight as u32))
		.sum();
	(sum % 10) as u8
}