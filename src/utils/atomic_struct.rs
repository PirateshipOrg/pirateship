// Copyright (c) Shubham Mishra. All rights reserved.
// Licensed under the MIT License.

use std::sync::Arc;

use crossbeam::atomic::AtomicCell;

/// AtomicStruct is the atomically settable version of any struct T.
/// Useful for reconfiguration, where the struct is updated very less.
/// So the overhead of locking will be unnecessarily high.
/// See usage in AtomicConfig and AtomicKeyStore.
pub struct AtomicStruct<T>(pub Arc<AtomicCell<Arc<Box<T>>>>);

impl<T> AtomicStruct<T> {
    pub fn new(init: T) -> Self {
        Self(Arc::new(AtomicCell::new(Arc::new(Box::new(init)))))
    }

    pub fn get(&self) -> Arc<Box<T>> {
        let ptr = self.0.as_ptr();
        unsafe { ptr.as_ref().unwrap() }.clone()
    }

    pub fn set(&self, val: Box<T>) {
        self.0.store(Arc::new(val));
    }

    pub fn is_lock_free() -> bool {
        AtomicCell::<Arc<Box<T>>>::is_lock_free()
    }
}

impl<T> Clone for AtomicStruct<T> {
    fn clone(&self) -> Self {
        AtomicStruct(self.0.clone())
    }
}
