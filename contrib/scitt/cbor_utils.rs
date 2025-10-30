use serde::{Deserialize, Serialize};
use serde_cbor;

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