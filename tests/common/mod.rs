use std::fmt;

/// Asserts two iterators are equal.
pub fn check_iter_eq<I, J, T>(mut i: I, mut j: J)
where
    I: Iterator<Item = T>,
    J: Iterator<Item = T>,
    T: PartialEq + fmt::Debug,
{
    loop {
        match (i.next(), j.next()) {
            (Some(x), Some(y)) => assert_eq!(x, y),
            (None, Some(y)) => panic!("second iterator yielded {:?}, first iterator empty", y),
            (Some(x), None) => panic!("first iterator yielded {:?}, second iterator empty", x),
            (None, None) => return,
        }
    }
}
