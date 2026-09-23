use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

use crate::model::{ActionRequest, ActionResponse, LaunchContext, ReceiptIndexRow, Refusal};

pub const FRAME_LIMIT: usize = 16_384;
pub const CONTROL_FRAME_LIMIT: usize = 65_536;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum ControlRequest {
    Ping,
    Status,
    OpenDiagnostic {
        challenge: String,
        context: LaunchContext,
        action: ActionRequest,
    },
    ReceiptList,
    ReceiptShow {
        receipt_id: String,
    },
    ReceiptVerify {
        receipt_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ControlResponse {
    Pong,
    Status {
        status: Box<crate::control::AuthorityStatus>,
    },
    SessionComplete {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    ReceiptList {
        receipts: Vec<ReceiptIndexRow>,
    },
    ReceiptShow {
        canonical_receipt: String,
    },
    ReceiptVerified {
        receipt_id: String,
        classification: Box<crate::model::ProductClassification>,
        initialization_evidence: crate::model::InitializationEvidence,
    },
    Refusal {
        code: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionActionRequest {
    pub session_id: String,
    pub execution_binding_id: String,
    pub action: ActionRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionActionResponse {
    Success { action: Box<ActionResponse> },
    Refusal { code: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReceiptResponse {
    List { receipts: Vec<ReceiptIndexRow> },
    Show { canonical_receipt: String },
    Verified { receipt_id: String },
    Refusal { code: String },
}

pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<(), Refusal> {
    write_bounded_frame(writer, value, FRAME_LIMIT)
}

pub fn write_control_frame<T: Serialize>(
    writer: &mut impl Write,
    value: &T,
) -> Result<(), Refusal> {
    write_bounded_frame(writer, value, CONTROL_FRAME_LIMIT)
}

fn write_bounded_frame<T: Serialize>(
    writer: &mut impl Write,
    value: &T,
    limit: usize,
) -> Result<(), Refusal> {
    let bytes = serde_jcs::to_vec(value).map_err(|_| Refusal::new("invalid_frame"))?;
    if bytes.len() > limit {
        return Err(Refusal::new("frame_too_large"));
    }
    let length = u32::try_from(bytes.len()).map_err(|_| Refusal::new("frame_too_large"))?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|_| writer.write_all(&bytes))
        .map_err(|_| Refusal::new("transport_failed"))
}

pub fn read_frame<T: serde::de::DeserializeOwned + Serialize>(
    reader: &mut impl Read,
) -> Result<T, Refusal> {
    read_bounded_frame(reader, FRAME_LIMIT)
}

pub fn read_control_frame<T: serde::de::DeserializeOwned + Serialize>(
    reader: &mut impl Read,
) -> Result<T, Refusal> {
    read_bounded_frame(reader, CONTROL_FRAME_LIMIT)
}

fn read_bounded_frame<T: serde::de::DeserializeOwned + Serialize>(
    reader: &mut impl Read,
    limit: usize,
) -> Result<T, Refusal> {
    let mut prefix = [0_u8; 4];
    reader
        .read_exact(&mut prefix)
        .map_err(|_| Refusal::new("invalid_frame"))?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > limit {
        return Err(Refusal::new("frame_too_large"));
    }
    let mut bytes = vec![0_u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| Refusal::new("invalid_frame"))?;
    let mut trailing = [0_u8; 1];
    if reader
        .read(&mut trailing)
        .map_err(|_| Refusal::new("invalid_frame"))?
        != 0
    {
        return Err(Refusal::new("invalid_frame"));
    }
    crate::audit::decode_canonical(&bytes, limit, "invalid_frame")
}
