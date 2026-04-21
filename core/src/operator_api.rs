use crate::hex_bytes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RollupSubmissionKind {
    ConfigureVerifier,
    ConfigureBridge,
    Shield,
    Transfer,
    Unshield,
    Withdraw,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RollupSubmissionTransport {
    DirectInbox,
    Dal,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RollupSubmissionStatus {
    PendingDal,
    CommitmentIncluded,
    Attested,
    SubmittedToL1,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollupDalChunk {
    pub slot_index: u16,
    pub published_level: i32,
    pub payload_len: usize,
    pub commitment: String,
    pub operation_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitRollupMessageReq {
    pub kind: RollupSubmissionKind,
    pub rollup_address: String,
    #[serde(with = "hex_bytes")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollupSubmission {
    pub id: String,
    pub kind: RollupSubmissionKind,
    pub rollup_address: String,
    pub status: RollupSubmissionStatus,
    pub transport: RollupSubmissionTransport,
    pub operation_hash: Option<String>,
    pub dal_chunks: Vec<RollupDalChunk>,
    pub commitment: Option<String>,
    pub published_level: Option<i32>,
    pub slot_index: Option<u16>,
    pub payload_hash: Option<String>,
    pub payload_len: usize,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmitRollupMessageResp {
    pub submission: RollupSubmission,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_request_hex_roundtrip() {
        let req = SubmitRollupMessageReq {
            kind: RollupSubmissionKind::ConfigureBridge,
            rollup_address: "sr1abc".into(),
            payload: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"deadbeef\""));
        let decoded: SubmitRollupMessageReq = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, req);
    }
}
