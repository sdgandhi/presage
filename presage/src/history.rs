//! Linked-device history transfer support.
//!
//! Signal may include an ephemeral backup key in the provisioning envelope for
//! a secondary device.  The primary then uploads a device-transfer archive,
//! which the newly linked device retrieves from the authenticated transfer
//! endpoint and decrypts with that key.

use std::time::{Duration, Instant};

use libsignal_message_backup::{
    backup::{serialize::Backup, Purpose},
    frame::CursorFactory,
    key::MessageBackupKey,
    BackupReader,
};
use libsignal_service::{
    configuration::Endpoint,
    libsignal_account_keys::BackupKey,
    protocol::Aci,
    push_service::{HttpAuthOverride, PushService},
};
use reqwest::{Method, StatusCode};
use serde::Deserialize;
use serde_json::Value;

use crate::store::StoreError;
use crate::Error;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);

/// One-time credentials delivered while linking a secondary device.
///
/// This value deliberately does not implement `Debug` or serialization so the
/// ephemeral backup key cannot be logged or persisted accidentally.
pub struct LinkedDeviceHistory {
    backup_key: [u8; 32],
}

impl LinkedDeviceHistory {
    pub(crate) fn new(backup_key: [u8; 32]) -> Self {
        Self { backup_key }
    }
}

/// The result selected by the primary device during link-and-sync.
pub enum HistoryTransferResult {
    Archive(HistoryArchive),
    ContinueWithoutUpload,
    RelinkRequested,
}

/// A validated Signal device-transfer archive.
///
/// The canonical representation contains recipients, chats, messages, calls,
/// reactions, formatting ranges, and attachment pointers. Keeping this as a
/// value lets clients import only the data their store supports while all
/// cryptographic validation stays inside libsignal.
pub struct HistoryArchive {
    value: Value,
}

impl HistoryArchive {
    pub fn as_value(&self) -> &Value {
        &self.value
    }

    pub fn into_value(self) -> Value {
        self.value
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum TransferArchiveResponse {
    Archive { cdn: u32, key: String },
    Error { error: TransferArchiveError },
}

#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum TransferArchiveError {
    RelinkRequested,
    ContinueWithoutUpload,
}

pub(crate) async fn download<S: StoreError>(
    push_service: PushService,
    aci: Aci,
    credentials: LinkedDeviceHistory,
    timeout: Duration,
) -> Result<HistoryTransferResult, Error<S>> {
    let started = Instant::now();
    let archive = loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(Error::HistoryTransfer(
                "timed out waiting for the primary device".into(),
            ));
        }
        let request_timeout = remaining.min(REQUEST_TIMEOUT).as_secs().max(1);
        let endpoint = Endpoint::service(format!(
            "/v1/devices/transfer_archive?timeout={request_timeout}"
        ));
        let response = push_service
            .request(Method::GET, endpoint, HttpAuthOverride::NoOverride)?
            .send()
            .await
            .map_err(libsignal_service::prelude::ServiceError::from)?;
        if response.status() == StatusCode::NO_CONTENT {
            continue;
        }
        if !response.status().is_success() {
            return Err(Error::HistoryTransfer(format!(
                "transfer endpoint returned {}",
                response.status()
            )));
        }
        break response
            .json::<TransferArchiveResponse>()
            .await
            .map_err(|error| Error::HistoryTransfer(error.to_string()))?;
    };

    let (cdn, key) = match archive {
        TransferArchiveResponse::Archive { cdn, key } => (cdn, key),
        TransferArchiveResponse::Error {
            error: TransferArchiveError::ContinueWithoutUpload,
        } => return Ok(HistoryTransferResult::ContinueWithoutUpload),
        TransferArchiveResponse::Error {
            error: TransferArchiveError::RelinkRequested,
        } => return Ok(HistoryTransferResult::RelinkRequested),
    };

    let response = push_service
        .request(
            Method::GET,
            Endpoint::cdn(cdn, format!("attachments/{key}")),
            HttpAuthOverride::Unidentified,
        )?
        .send()
        .await
        .map_err(libsignal_service::prelude::ServiceError::from)?;
    if !response.status().is_success() {
        return Err(Error::HistoryTransfer(format!(
            "archive download returned {}",
            response.status()
        )));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|error| Error::HistoryTransfer(error.to_string()))?;

    let backup_key: BackupKey = BackupKey(credentials.backup_key);
    let backup_id = backup_key.derive_backup_id(&aci);
    let message_key = MessageBackupKey::derive(&backup_key, &backup_id, None);
    let reader = BackupReader::new_encrypted_compressed(
        &message_key,
        CursorFactory::new(&bytes),
        Purpose::DeviceTransfer,
    )
    .await
    .map_err(|error| Error::HistoryTransfer(error.to_string()))?;
    let result = reader.read_all().await;
    let completed = result
        .result
        .map_err(|error| Error::HistoryTransfer(error.to_string()))?;
    let value = serde_json::to_value(Backup::from(completed))?;
    Ok(HistoryTransferResult::Archive(HistoryArchive { value }))
}
