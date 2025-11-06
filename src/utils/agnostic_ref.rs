use std::ops::Deref;

enum AgnosticRefType<'a, T> {
    Borrowed(&'a T),
    Owned(T),
}

/// This mocks C++ style Rvalue reference.
/// Either you create this from a borrowed pointer
/// or this struct will own the object.
/// So that when this struct drops, no change to the borrowed pointer.
/// But owned object will be dropped too.
pub struct AgnosticRef<'a, T> {
    data: AgnosticRefType<'a, T>,
}

impl<'a, T> Deref for AgnosticRef<'a, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match &self.data {
            AgnosticRefType::Borrowed(ptr) => *ptr,
            AgnosticRefType::Owned(val) => val,
        }
    }
}

impl<'a, T> From<T> for AgnosticRef<'a, T> {
    fn from(value: T) -> Self {
        Self {
            data: AgnosticRefType::Owned(value),
        }
    }
}

impl<'a, T> From<&'a T> for AgnosticRef<'a, T> {
    fn from(value: &'a T) -> Self {
        Self {
            data: AgnosticRefType::Borrowed(value),
        }
    }
}
