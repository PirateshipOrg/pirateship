use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::ptr;

// Import the unsafe FFI functions from the same crate
use crate::{didx509_free_result, didx509_resolve, didx509_resolve_jwk};

/// Error type for DIDX509 operations
#[derive(Debug, thiserror::Error)]
pub enum DidX509Error {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Resolution failed: {0}")]
    ResolutionFailed(String),
    #[error("Memory allocation failed")]
    MemoryAllocation,
    #[error("String conversion failed")]
    StringConversion,
}

/// Result type for DIDX509 operations
pub type DidX509Result<T> = Result<T, DidX509Error>;

/// Main struct for DIDX509 operations
pub struct DidX509Resolver;

impl DidX509Resolver {
    /// Create a new DIDX509 resolver
    pub fn new() -> Self {
        Self
    }

    /// Resolve a DID:x509 identifier to a DID document
    ///
    /// # Arguments
    /// * `chain_pem` - PEM encoded certificate chain
    /// * `did` - The DID:x509 identifier to resolve
    /// * `ignore_time` - Whether to ignore certificate validity time checks
    ///
    /// # Returns
    /// A JSON string containing the resolved DID document
    pub fn resolve(&self, chain_pem: &str, did: &str, ignore_time: bool) -> DidX509Result<String> {
        let chain_cstring = CString::new(chain_pem)
            .map_err(|_| DidX509Error::InvalidInput("Invalid PEM chain".to_string()))?;

        let did_cstring =
            CString::new(did).map_err(|_| DidX509Error::InvalidInput("Invalid DID".to_string()))?;

        let mut result: *mut c_char = ptr::null_mut();
        let mut result_length: c_int = 0;

        let return_code = unsafe {
            didx509_resolve(
                chain_cstring.as_ptr(),
                did_cstring.as_ptr(),
                if ignore_time { 1 } else { 0 },
                &mut result,
                &mut result_length,
            )
        };

        if return_code != 0 {
            return Err(DidX509Error::ResolutionFailed(
                format!("Failed to resolve DID, error code {}", return_code),
            ));
        }

        if result.is_null() {
            return Err(DidX509Error::MemoryAllocation);
        }

        let result_str = unsafe {
            let cstr = CStr::from_ptr(result);
            let rust_str = cstr
                .to_str()
                .map_err(|_| DidX509Error::StringConversion)?
                .to_string();

            // Free the allocated memory
            didx509_free_result(result);

            rust_str
        };

        Ok(result_str)
    }

    /// Resolve a DID:x509 identifier to a JWK
    ///
    /// # Arguments
    /// * `chain_pem` - Vector of PEM encoded certificates
    /// * `did` - The DID:x509 identifier to resolve
    /// * `ignore_time` - Whether to ignore certificate validity time checks
    ///
    /// # Returns
    /// A JSON string containing the JWK
    pub fn resolve_jwk(
        &self,
        chain_pem: &[String],
        did: &str,
        ignore_time: bool,
    ) -> DidX509Result<String> {
        let did_cstring =
            CString::new(did).map_err(|_| DidX509Error::InvalidInput("Invalid DID".to_string()))?;

        // Convert Vec<String> to Vec<CString> and then to Vec<*const c_char>
        let chain_cstrings: Result<Vec<CString>, _> =
            chain_pem.iter().map(|s| CString::new(s.as_str())).collect();

        let chain_cstrings = chain_cstrings
            .map_err(|_| DidX509Error::InvalidInput("Invalid PEM chain".to_string()))?;

        let mut chain_ptrs: Vec<*const c_char> =
            chain_cstrings.iter().map(|cs| cs.as_ptr()).collect();

        let mut result: *mut c_char = ptr::null_mut();
        let mut result_length: c_int = 0;

        let return_code = unsafe {
            didx509_resolve_jwk(
                chain_ptrs.as_mut_ptr(),
                chain_ptrs.len() as c_int,
                did_cstring.as_ptr(),
                if ignore_time { 1 } else { 0 },
                &mut result,
                &mut result_length,
            )
        };

        if return_code != 0 {
            return Err(DidX509Error::ResolutionFailed(
                "Failed to resolve JWK".to_string(),
            ));
        }

        if result.is_null() {
            return Err(DidX509Error::MemoryAllocation);
        }

        let result_str = unsafe {
            let cstr = CStr::from_ptr(result);
            let rust_str = cstr
                .to_str()
                .map_err(|_| DidX509Error::StringConversion)?
                .to_string();

            // Free the allocated memory
            didx509_free_result(result);

            rust_str
        };

        Ok(result_str)
    }
}

impl Default for DidX509Resolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolver_creation() {
        let resolver = DidX509Resolver::new();
        // Just test that we can create a resolver without panicking
        assert_eq!(std::mem::size_of_val(&resolver), 0);
    }

    #[test]
    fn test_invalid_inputs() {
        let resolver = DidX509Resolver::new();

        // Test with empty strings
        let result = resolver.resolve("", "", false);
        assert!(result.is_err());

        // Test with invalid DID format
        let result = resolver.resolve("some_pem", "invalid_did", false);
        assert!(result.is_err());
    }
}
