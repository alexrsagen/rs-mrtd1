# mrtd
Helper utilities for communicating with eMRTDs / ePassports

> **Warning**
> This library is not currently intended for any production use. You have been warned.

## Usage
See https://github.com/alexrsagen/rs-nfc example `read_mrtd` for example usage.

## TODO
Feel free to submit a PR for any of these tasks:
- Improve error reporting
	- Remove all use of format!() or static strings for errors.
	- Replace all use of `BoxError`/`BoxResult` with a better error type (like `src/mrz/error.rs`)
- Add tests
	- Specifically test use of `DO'85'` in `apdu::command::borrowed::ApduCommand::to_protected` and `apdu::response::owned::ApduResponse::from_protected`. Not sure if this is working or done correctly.
- Add fuzzing
- Make more use of external crates, where suitable (improved code quality, readability, functionality, etc)