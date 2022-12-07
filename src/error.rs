// TODO: Implement a proper error type
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type BoxResult<T> = Result<T, BoxError>;