//! Typed identifiers.  All are plain integers so they pack into 2–4 bytes on the
//! wire; the newtypes stop us from passing a card id where a group id belongs.

use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct CardId(pub u32);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GroupId(pub u16);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProgramId(pub u16);

/// Index of a control-word period since the Unix epoch.  Period length is
/// chosen by the headend (short: 1–4 s) and is the unit of CW lifetime.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeriodIndex(pub u64);

macro_rules! impl_id {
    ($t:ident, $inner:ty, $label:literal) => {
        impl $t {
            pub const fn get(self) -> $inner {
                self.0
            }
        }
        impl From<$inner> for $t {
            fn from(v: $inner) -> Self {
                Self(v)
            }
        }
        impl fmt::Debug for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($label, "({})"), self.0)
            }
        }
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

impl_id!(CardId, u32, "card");
impl_id!(GroupId, u16, "group");
impl_id!(ProgramId, u16, "program");
impl_id!(PeriodIndex, u64, "period");

impl PeriodIndex {
    pub const fn next(self) -> Self {
        Self(self.0 + 1)
    }
    pub const fn saturating_sub(self, n: u64) -> Self {
        Self(self.0.saturating_sub(n))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_and_display() {
        assert!(CardId(2) > CardId(1));
        assert_eq!(format!("{}", GroupId(9)), "9");
        assert_eq!(format!("{:?}", CardId(9)), "card(9)");
        assert_eq!(PeriodIndex(5).next(), PeriodIndex(6));
        assert_eq!(PeriodIndex(1).saturating_sub(4), PeriodIndex(0));
    }
}
