//! didx509-sys: DID:x509 resolution library
//!
//! This crate provides both low-level FFI bindings and safe Rust wrappers
//! for the didx509 C++ library.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod didx509;

// Re-export the main public API
pub use didx509::{DidX509Error, DidX509Resolver, DidX509Result};

use std::os::raw::{c_char, c_int};

extern "C" {
    /// Resolve a DID:x509 identifier to a DID document
    ///
    /// # Safety
    /// This function is unsafe because it:
    /// - Dereferences raw pointers
    /// - Expects null-terminated C strings
    /// - Allocates memory that must be freed with didx509_free_result
    ///
    /// # Parameters
    /// * `chain_pem` - Null-terminated PEM encoded certificate chain
    /// * `did` - Null-terminated DID:x509 identifier
    /// * `ignore_time` - 1 to ignore time validity, 0 to check
    /// * `result` - Output pointer to allocated result string
    /// * `result_length` - Output length of result string
    ///
    /// # Returns
    /// 0 on success, non-zero on error
    pub fn didx509_resolve(
        chain_pem: *const c_char,
        did: *const c_char,
        ignore_time: c_int,
        result: *mut *mut c_char,
        result_length: *mut c_int,
    ) -> c_int;

    /// Resolve a DID:x509 identifier to a JWK
    ///
    /// # Safety
    /// This function is unsafe because it:
    /// - Dereferences raw pointers
    /// - Expects null-terminated C strings
    /// - Allocates memory that must be freed with didx509_free_result
    ///
    /// # Parameters
    /// * `chain_pem_array` - Array of null-terminated PEM strings
    /// * `chain_length` - Length of the chain array
    /// * `did` - Null-terminated DID:x509 identifier
    /// * `ignore_time` - 1 to ignore time validity, 0 to check
    /// * `result` - Output pointer to allocated result string
    /// * `result_length` - Output length of result string
    ///
    /// # Returns
    /// 0 on success, non-zero on error
    pub fn didx509_resolve_jwk(
        chain_pem_array: *mut *const c_char,
        chain_length: c_int,
        did: *const c_char,
        ignore_time: c_int,
        result: *mut *mut c_char,
        result_length: *mut c_int,
    ) -> c_int;

    /// Free memory allocated by didx509_resolve or didx509_resolve_jwk
    ///
    /// # Safety
    /// This function is unsafe because it frees raw memory.
    /// Only call this on pointers returned by the resolve functions.
    ///
    /// # Parameters
    /// * `result` - Pointer to free (from resolve functions)
    pub fn didx509_free_result(result: *mut c_char);
}
