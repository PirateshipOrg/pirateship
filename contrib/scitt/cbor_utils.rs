use serde::{Deserialize, Serialize};
use serde_cbor;

// Error codes for CBOR operations
pub const _CBOR_ERROR_TITLE: &str = "title";
pub const _CBOR_ERROR_DETAIL: &str = "detail";

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OperationResponse {
    #[serde(rename = "OperationId")]
    pub operation_id: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "EntryId", skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    #[serde(rename = "Error", skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorInfo>,
}

/// Creates a CBOR-encoded operation response
/// 
/// # Arguments
/// * `operation_id` - The unique identifier for the operation
/// * `status` - The status of the operation (e.g., "running", "succeeded", "failed")
/// * `entry_id` - Optional entry identifier if the operation created an entry
/// * `error_code` - Optional error code if the operation failed
/// * `error_message` - Optional error message providing details about the failure
/// 
/// # Returns
/// A vector of bytes containing the CBOR-encoded operation response
/// 
/// # Errors
/// Returns an error if CBOR encoding fails
pub fn operation_props_to_cbor(
    operation_id: &str,
    status: &str,
    entry_id: Option<&str>,
    error_code: Option<&str>,
    error_message: Option<&str>,
) -> Result<Vec<u8>, serde_cbor::Error> {
    let error = if error_code.is_some() || error_message.is_some() {
        Some(ErrorInfo {
            title: error_code.map(|s| s.to_string()),
            detail: error_message.map(|s| s.to_string()),
        })
    } else {
        None
    };

    let operation = OperationResponse {
        operation_id: operation_id.to_string(),
        status: status.to_string(),
        entry_id: entry_id.map(|s| s.to_string()),
        error,
    };

    serde_cbor::to_vec(&operation)
}

/// Deserializes a CBOR-encoded operation response
/// 
/// # Arguments
/// * `cbor_data` - The CBOR-encoded bytes to deserialize
/// 
/// # Returns
/// The deserialized operation response
/// 
/// # Errors
/// Returns an error if CBOR decoding fails
pub fn _cbor_to_operation_props(cbor_data: &[u8]) -> Result<OperationResponse, serde_cbor::Error> {
    serde_cbor::from_slice(cbor_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_props_to_cbor_success() {
        let cbor_data = operation_props_to_cbor(
            "op-123",
            "succeeded",
            Some("entry-456"),
            None,
            None,
        ).unwrap();

        // Verify we can deserialize it back
        let operation = _cbor_to_operation_props(&cbor_data).unwrap();
        assert_eq!(operation.operation_id, "op-123");
        assert_eq!(operation.status, "succeeded");
        assert_eq!(operation.entry_id, Some("entry-456".to_string()));
        assert!(operation.error.is_none());
    }

    #[test]
    fn test_operation_props_to_cbor_with_error() {
        let cbor_data = operation_props_to_cbor(
            "op-789",
            "failed",
            None,
            Some("E001"),
            Some("Operation failed due to invalid input"),
        ).unwrap();

        // Verify we can deserialize it back
        let operation = _cbor_to_operation_props(&cbor_data).unwrap();
        assert_eq!(operation.operation_id, "op-789");
        assert_eq!(operation.status, "failed");
        assert!(operation.entry_id.is_none());
        
        let error = operation.error.unwrap();
        assert_eq!(error.title, Some("E001".to_string()));
        assert_eq!(error.detail, Some("Operation failed due to invalid input".to_string()));
    }

    #[test]
    fn test_operation_props_to_cbor_minimal() {
        let cbor_data = operation_props_to_cbor(
            "op-minimal",
            "running",
            None,
            None,
            None,
        ).unwrap();

        // Verify we can deserialize it back
        let operation = _cbor_to_operation_props(&cbor_data).unwrap();
        assert_eq!(operation.operation_id, "op-minimal");
        assert_eq!(operation.status, "running");
        assert!(operation.entry_id.is_none());
        assert!(operation.error.is_none());
    }
}