//! Monotonic milliseconds and the slide window that lets a receiver hold a
//! *pre-delivered* control word before it becomes active.

use core::fmt;

/// Milliseconds since the epoch (or since simulation start).  Signed so we can
/// reason about schedule offsets without wrapping care.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Millis(pub i64);

impl Millis {
    pub const ZERO: Millis = Millis(0);

    pub const fn from_secs(s: i64) -> Self {
        Self(s * 1000)
    }

    pub const fn as_secs_f64(self) -> f64 {
        self.0 as f64 / 1000.0
    }

    pub const fn saturating_add(self, ms: i64) -> Self {
        Self(self.0.saturating_add(ms))
    }

    pub const fn saturating_sub(self, ms: i64) -> Self {
        Self(self.0.saturating_sub(ms))
    }

    pub const fn elapsed(self, since: Millis) -> i64 {
        self.0 - since.0
    }
}

impl fmt::Debug for Millis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.0)
    }
}

impl fmt::Display for Millis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.3}s", self.0 as f64 / 1000.0)
    }
}

impl core::ops::Add<i64> for Millis {
    type Output = Millis;
    fn add(self, rhs: i64) -> Millis {
        Millis(self.0 + rhs)
    }
}

impl core::ops::Sub<Millis> for Millis {
    type Output = i64;
    fn sub(self, rhs: Millis) -> i64 {
        self.0 - rhs.0
    }
}

/// Half-open time window `[start, end)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TimeWindow {
    pub start: Millis,
    pub end: Millis,
}

impl TimeWindow {
    pub fn new(start: Millis, end: Millis) -> Self {
        Self { start, end }
    }

    pub fn contains(&self, t: Millis) -> bool {
        t >= self.start && t < self.end
    }

    pub fn duration_ms(&self) -> i64 {
        self.end.0 - self.start.0
    }

    pub fn overlaps(&self, other: &TimeWindow) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Intersection, or `None` when disjoint.
    pub fn intersect(&self, other: &TimeWindow) -> Option<TimeWindow> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        (start < end).then_some(TimeWindow { start, end })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_semantics() {
        let w = TimeWindow::new(Millis(100), Millis(200));
        assert!(w.contains(Millis(100)));
        assert!(!w.contains(Millis(200)));
        assert_eq!(w.duration_ms(), 100);
        let o = TimeWindow::new(Millis(150), Millis(250));
        assert!(w.overlaps(&o));
        assert_eq!(
            w.intersect(&o).unwrap(),
            TimeWindow::new(Millis(150), Millis(200))
        );
        let d = TimeWindow::new(Millis(200), Millis(300));
        assert!(!w.overlaps(&d));
        assert!(w.intersect(&d).is_none());
    }
}
