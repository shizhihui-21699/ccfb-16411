use core::fmt;

/// Errors shared by every crate in the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A byte slice ended before a field could be decoded.
    Truncated { need: usize, have: usize },
    /// A length prefix or array size was outside the accepted range.
    BadLength { field: &'static str, value: usize },
    /// A framing marker byte (version, tag, type) was not what the decoder expected.
    BadMarker { field: &'static str, value: u8 },
    /// The CRC-32 trailer did not match the payload.
    BadCrc { expect: u32, got: u32 },
    /// The AES-CMAC / tag comparison failed on an authenticated message.
    AuthFailed,
    /// A signature or MAC key was the wrong size.
    BadKeySize(usize),
    /// The frame describes a period or epoch that the receiver cannot use.
    StaleFrame { frame: u64, newest: u64 },
    /// No cryptographic material exists for the requested identifier.
    Unknown(&'static str),
    /// A tunable was set to a value the model rejects.
    BadParam { name: &'static str, detail: String },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated { need, have } => {
                write!(f, "truncated buffer: need {need} bytes, have {have}")
            }
            Error::BadLength { field, value } => {
                write!(f, "bad length for {field}: {value}")
            }
            Error::BadMarker { field, value } => {
                write!(f, "bad marker for {field}: {value:#04x}")
            }
            Error::BadCrc { expect, got } => {
                write!(f, "crc mismatch: expected {expect:#010x}, got {got:#010x}")
            }
            Error::AuthFailed => f.write_str("authentication tag rejected"),
            Error::BadKeySize(n) => write!(f, "bad key size: {n} bytes"),
            Error::StaleFrame { frame, newest } => {
                write!(f, "stale frame {frame}, newest is {newest}")
            }
            Error::Unknown(what) => write!(f, "unknown {what}"),
            Error::BadParam { name, detail } => write!(f, "bad parameter {name}: {detail}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
