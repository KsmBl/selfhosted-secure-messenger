//! 5×5 unlock pattern (ADR-0005).
//!
//! A pattern is a sequence of dot presses on a 5×5 grid. Dots are numbered
//! row by row from 0 (top left) to 24 (bottom right); every dot may be
//! pressed any number of times.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const GRID_SIZE: u8 = 5;
pub const DOT_COUNT: u8 = GRID_SIZE * GRID_SIZE;
pub const MIN_LEN: usize = 6;
pub const MAX_LEN: usize = 64;
/// Patterns using fewer distinct dots than this are rejected as trivial.
pub const MIN_DISTINCT_DOTS: usize = 3;

const ENCODING_DOMAIN: &[u8] = b"ssm-pattern-v1";
const CORNERS: [u8; 4] = [0, 4, 20, 24];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PatternError {
    #[error("pattern must have at least {MIN_LEN} presses")]
    TooShort,
    #[error("pattern must have at most {MAX_LEN} presses")]
    TooLong,
    #[error("dot index {0} is outside the 5x5 grid")]
    InvalidDot(u8),
    #[error("pattern uses fewer than {MIN_DISTINCT_DOTS} different dots")]
    TooFewDistinctDots,
    #[error("pattern only uses a single row, column or diagonal")]
    SingleLine,
    #[error("pattern only uses the four corners")]
    CornersOnly,
}

/// A validated unlock pattern. The dot sequence is wiped from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Pattern {
    dots: Vec<u8>,
}

impl Pattern {
    pub fn new(dots: Vec<u8>) -> Result<Self, PatternError> {
        let pattern = Self { dots };
        pattern.validate()?;
        Ok(pattern)
    }

    pub fn len(&self) -> usize {
        self.dots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.dots.is_empty()
    }

    /// Canonical byte encoding used as Argon2id input:
    /// `"ssm-pattern-v1" || len (u8) || dots (u8 each)`.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(ENCODING_DOMAIN.len() + 1 + self.dots.len()));
        out.extend_from_slice(ENCODING_DOMAIN);
        // Length fits in u8 because validate() enforces MAX_LEN = 64.
        out.push(self.dots.len() as u8);
        out.extend_from_slice(&self.dots);
        out
    }

    fn validate(&self) -> Result<(), PatternError> {
        if self.dots.len() < MIN_LEN {
            return Err(PatternError::TooShort);
        }
        if self.dots.len() > MAX_LEN {
            return Err(PatternError::TooLong);
        }
        if let Some(&dot) = self.dots.iter().find(|&&d| d >= DOT_COUNT) {
            return Err(PatternError::InvalidDot(dot));
        }

        let mut used = [false; DOT_COUNT as usize];
        for &d in &self.dots {
            used[d as usize] = true;
        }
        let distinct: Vec<u8> = (0..DOT_COUNT).filter(|&d| used[d as usize]).collect();

        if distinct.len() < MIN_DISTINCT_DOTS {
            return Err(PatternError::TooFewDistinctDots);
        }
        if distinct.iter().all(|d| CORNERS.contains(d)) {
            return Err(PatternError::CornersOnly);
        }
        if lies_on_single_line(&distinct) {
            return Err(PatternError::SingleLine);
        }
        Ok(())
    }
}

impl std::fmt::Debug for Pattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pattern").field("len", &self.dots.len()).finish_non_exhaustive()
    }
}

/// True if all dots lie in one row, one column or one of the two main diagonals.
fn lies_on_single_line(dots: &[u8]) -> bool {
    let row = |d: u8| d / GRID_SIZE;
    let col = |d: u8| d % GRID_SIZE;
    let same_row = dots.iter().all(|&d| row(d) == row(dots[0]));
    let same_col = dots.iter().all(|&d| col(d) == col(dots[0]));
    let main_diag = dots.iter().all(|&d| row(d) == col(d));
    let anti_diag = dots.iter().all(|&d| row(d) + col(d) == GRID_SIZE - 1);
    same_row || same_col || main_diag || anti_diag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_reasonable_pattern_with_repeats() {
        let p = Pattern::new(vec![6, 12, 6, 18, 7, 7]).unwrap();
        assert_eq!(p.len(), 6);
    }

    #[test]
    fn rejects_short_long_and_out_of_range() {
        assert_eq!(Pattern::new(vec![0, 6, 12, 18, 7]).unwrap_err(), PatternError::TooShort);
        assert_eq!(Pattern::new(vec![1, 7, 13].repeat(22)).unwrap_err(), PatternError::TooLong);
        assert_eq!(Pattern::new(vec![0, 6, 12, 18, 7, 25]).unwrap_err(), PatternError::InvalidDot(25));
    }

    #[test]
    fn rejects_trivial_patterns() {
        assert_eq!(Pattern::new(vec![3; 8]).unwrap_err(), PatternError::TooFewDistinctDots);
        assert_eq!(Pattern::new(vec![1, 2, 1, 2, 1, 2]).unwrap_err(), PatternError::TooFewDistinctDots);
        assert_eq!(Pattern::new(vec![0, 1, 2, 3, 4, 0]).unwrap_err(), PatternError::SingleLine);
        assert_eq!(Pattern::new(vec![2, 7, 12, 17, 22, 17]).unwrap_err(), PatternError::SingleLine);
        assert_eq!(Pattern::new(vec![0, 6, 12, 18, 24, 18]).unwrap_err(), PatternError::SingleLine);
        assert_eq!(Pattern::new(vec![4, 8, 12, 16, 20, 4]).unwrap_err(), PatternError::SingleLine);
        assert_eq!(Pattern::new(vec![0, 4, 24, 20, 0, 4]).unwrap_err(), PatternError::CornersOnly);
    }

    #[test]
    fn encoding_is_domain_separated_and_order_sensitive() {
        let a = Pattern::new(vec![0, 6, 12, 18, 7, 8]).unwrap();
        let b = Pattern::new(vec![8, 7, 18, 12, 6, 0]).unwrap();
        let enc = a.encode();
        assert!(enc.starts_with(ENCODING_DOMAIN));
        assert_eq!(enc[ENCODING_DOMAIN.len()], 6);
        assert_ne!(*a.encode(), *b.encode());
    }
}
