// SPDX-License-Identifier: Apache-2.0

//! A one-request worker for the separately pinned execution verifier.
//!
//! The hardware feature fixes dispatch to TDX and confines collateral lookup to
//! bytes supplied on stdin. The feature-off worker can only return unproven.
//! The parent owns process, CPU, memory, elapsed-time and output limits.

use execution_proof_verifier::protocol::{
    TdxWorkerRequest, TdxWorkerResponse, WorkerStatus, MAX_WORKER_REQUEST_BYTES,
};
use std::io::{Read, Write};

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("execution verifier worker protocol failed")]
pub struct WorkerProtocolError;

pub fn run_stdio() -> Result<(), WorkerProtocolError> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_WORKER_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| WorkerProtocolError)?;
    let request = TdxWorkerRequest::decode(&input).map_err(|_| WorkerProtocolError)?;
    let response = verify_request(&request)?;
    let encoded = response.encode().map_err(|_| WorkerProtocolError)?;
    std::io::stdout()
        .lock()
        .write_all(&encoded)
        .map_err(|_| WorkerProtocolError)
}

fn response(
    request: &TdxWorkerRequest,
    status: WorkerStatus,
    reason: &str,
    claims: Option<execution_proof_verifier::protocol::TdxClaims>,
) -> Result<TdxWorkerResponse, WorkerProtocolError> {
    TdxWorkerResponse::new(request, status, reason.into(), claims).map_err(|_| WorkerProtocolError)
}

fn request_profile(request: &TdxWorkerRequest) -> bool {
    let Ok(report) = hex::decode(&request.expected_report_data) else {
        return false;
    };
    let Ok(init) = hex::decode(&request.expected_mr_config_id) else {
        return false;
    };
    report.len() == 64
        && report[..48].iter().any(|byte| *byte != 0)
        && report[48..].iter().all(|byte| *byte == 0)
        && init.len() == 48
        && init.iter().any(|byte| *byte != 0)
}

fn verify_request(request: &TdxWorkerRequest) -> Result<TdxWorkerResponse, WorkerProtocolError> {
    request.validate().map_err(|_| WorkerProtocolError)?;
    if !request_profile(request) {
        return response(
            request,
            WorkerStatus::Invalid,
            "execution_profile_binding",
            None,
        );
    }
    #[cfg(feature = "execution-quote-worker-tdx")]
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|_| WorkerProtocolError)?;
        match runtime.block_on(hardware::verify(request)) {
            Ok(claims) => response(
                request,
                WorkerStatus::Verified,
                "tdx_verified",
                Some(claims),
            ),
            Err(hardware::Failure::Invalid(reason)) => {
                response(request, WorkerStatus::Invalid, reason, None)
            }
            Err(hardware::Failure::Unproven(reason)) => {
                response(request, WorkerStatus::Unproven, reason, None)
            }
        }
    }
    #[cfg(not(feature = "execution-quote-worker-tdx"))]
    response(
        request,
        WorkerStatus::Unproven,
        "tdx_verifier_unavailable",
        None,
    )
}

#[cfg(any(feature = "execution-quote-worker-tdx", test))]
fn normalized_claims(
    value: &serde_json::Value,
    request: &TdxWorkerRequest,
    evaluation_time: u64,
) -> Option<execution_proof_verifier::protocol::TdxClaims> {
    use execution_proof_verifier::protocol::TdxClaims;
    use sha2::{Digest, Sha384};

    fn field(value: &serde_json::Value, pointer: &str, bytes: usize) -> Option<String> {
        let text = value.pointer(pointer)?.as_str()?;
        if text.len() != bytes * 2 {
            return None;
        }
        let decoded = hex::decode(text).ok()?;
        Some(hex::encode(decoded))
    }

    let report_data = field(value, "/quote/body/report_data", 64)?;
    let mr_config_id = field(value, "/quote/body/mr_config_id", 48)?;
    if report_data != request.expected_report_data
        || mr_config_id != request.expected_mr_config_id
        || field(value, "/report_data", 64)? != report_data
        || field(value, "/init_data", 48)? != mr_config_id
    {
        return None;
    }
    let attributes = hex::decode(field(value, "/quote/body/td_attributes", 8)?).ok()?;
    let attributes = u64::from_le_bytes(attributes.try_into().ok()?);
    let debug = attributes & 1 != 0;
    if value.pointer("/td_attributes/debug")?.as_bool()? != debug {
        return None;
    }
    let tcb_status = value.get("tcb_status")?.as_str()?;
    if tcb_status.len() > 128 {
        return None;
    }
    // The upstream claims encode DCAP's collateral-expiration result as text.
    let expiration = value.get("collateral_expiration_status")?.as_str()?;
    let expiration = expiration.parse::<u32>().ok()?;
    if evaluation_time == 0 || evaluation_time > i64::MAX as u64 {
        return None;
    }
    Some(TdxClaims {
        evidence_sha384: hex::encode(Sha384::digest(&request.evidence_json)),
        report_data,
        mr_config_id,
        mr_td: field(value, "/quote/body/mr_td", 48)?,
        rtmrs: [
            field(value, "/quote/body/rtmr_0", 48)?,
            field(value, "/quote/body/rtmr_1", 48)?,
            field(value, "/quote/body/rtmr_2", 48)?,
            field(value, "/quote/body/rtmr_3", 48)?,
        ],
        debug,
        tcb_status: tcb_status.into(),
        collateral_expiration_status: expiration,
        evaluation_time_unix_seconds: evaluation_time,
    })
}

#[cfg(any(feature = "execution-quote-worker-tdx", test))]
pub(super) fn anonymous_collateral(bytes: &[u8]) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let mut file = tempfile::tempfile_in("/tmp")?;
    // tempfile's Unix fallback unlinks before returning, but ignores an unlink
    // error. Never put collateral in an inode that still has a directory link.
    if file.metadata()?.nlink() != 0 {
        return Err(std::io::Error::other("anonymous collateral unavailable"));
    }
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    Ok(file)
}

#[cfg(feature = "execution-quote-worker-tdx")]
mod hardware {
    use super::*;
    use crate::{InitDataHash, ReportData, VerifierConfig};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use key_value_storage::{KvStorageProvider, StorageBackendConfig};
    use serde::Deserialize;
    use std::{os::fd::AsRawFd, path::PathBuf, time::SystemTime};

    const RAW_QUOTE_BYTES: usize = 512 * 1024;

    pub(super) enum Failure {
        Invalid(&'static str),
        Unproven(&'static str),
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Evidence {
        cc_eventlog: Option<String>,
        quote: String,
    }

    pub(super) async fn verify(
        request: &TdxWorkerRequest,
    ) -> Result<execution_proof_verifier::protocol::TdxClaims, Failure> {
        let evidence: Evidence =
            execution_proof_verifier::schema::decode(&request.evidence_json, 1024 * 1024)
                .map_err(|_| Failure::Invalid("tdx_evidence_schema"))?;
        if evidence.cc_eventlog.is_some()
            || evidence.quote.is_empty()
            || evidence.quote.len() > RAW_QUOTE_BYTES.div_ceil(3) * 4
        {
            return Err(Failure::Invalid("tdx_evidence_profile"));
        }
        let raw_quote = STANDARD
            .decode(&evidence.quote)
            .map_err(|_| Failure::Invalid("tdx_quote_encoding"))?;
        if raw_quote.is_empty() || raw_quote.len() > RAW_QUOTE_BYTES {
            return Err(Failure::Invalid("tdx_quote_bounds"));
        }
        // Parse the exact supported collateral shape before creating a file.
        // No field in the bundle selects a path, URL or verifier configuration.
        let _: crate::intel_dcap::collateral_service::PlatformCollaterals =
            execution_proof_verifier::schema::decode(&request.collateral_json, 4 * 1024 * 1024)
                .map_err(|_| Failure::Invalid("tdx_collateral_schema"))?;
        let collateral = anonymous_collateral(&request.collateral_json)
            .map_err(|_| Failure::Unproven("collateral_staging_unavailable"))?;
        let path = PathBuf::from(format!("/proc/self/fd/{}", collateral.as_raw_fd()));
        let url = url::Url::from_file_path(&path)
            .map_err(|_| Failure::Unproven("collateral_staging_unavailable"))?;
        let config: VerifierConfig = serde_json::from_value(serde_json::json!({
            "dcap_verifier": { "collateral_service":url.as_str(), "tcb_update_type":"early" }
        }))
        .map_err(|_| Failure::Unproven("tdx_configuration_unavailable"))?;
        let selected = config
            .dcap_verifier
            .as_ref()
            .ok_or(Failure::Unproven("tdx_configuration_unavailable"))?;
        // Guard against any future configuration/schema fallback to network.
        let selected = serde_json::to_value(selected)
            .map_err(|_| Failure::Unproven("tdx_configuration_unavailable"))?;
        if selected
            .get("collateral_service")
            .and_then(|value| value.as_str())
            != Some(url.as_str())
        {
            return Err(Failure::Unproven("tdx_configuration_unavailable"));
        }
        let verifier = crate::to_verifier(
            &kbs_types::Tee::Tdx,
            Some(config),
            KvStorageProvider::new(StorageBackendConfig::default()),
        )
        .await
        .map_err(|_| Failure::Unproven("tdx_verifier_unavailable"))?;
        let expected_report = hex::decode(&request.expected_report_data)
            .map_err(|_| Failure::Invalid("execution_profile_binding"))?;
        let expected_init = hex::decode(&request.expected_mr_config_id)
            .map_err(|_| Failure::Invalid("execution_profile_binding"))?;
        let before = SystemTime::now();
        let evidence =
            execution_proof_verifier::schema::decode(&request.evidence_json, 1024 * 1024)
                .map_err(|_| Failure::Invalid("tdx_evidence_schema"))?;
        let claims = verifier
            .evaluate(
                evidence,
                &ReportData::Value(&expected_report),
                &InitDataHash::Value(&expected_init),
            )
            .await
            .map_err(|_| Failure::Unproven("tdx_verification_failed"))?;
        // Retain the anonymous inode until all offline PCS reads have finished.
        // SIGKILL also closes it; no destructor is required to unlink data.
        drop(collateral);
        let after = SystemTime::now();
        if after
            .duration_since(before)
            .map_or(true, |elapsed| elapsed.as_secs() > 30)
        {
            return Err(Failure::Unproven("verification_clock_unavailable"));
        }
        let evaluation_time = after
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| Failure::Unproven("verification_clock_unavailable"))?
            .as_secs();
        // This is the worker-observed current verification clock, not an exec
        // timestamp or the exact internal DCAP call timestamp. Historical
        // collateral-snapshot evaluation is outside this worker's profile.
        let mut claims = claims.into_iter();
        let (claim, class) = claims
            .next()
            .ok_or(Failure::Unproven("tdx_claims_unavailable"))?;
        if class != "cpu" || claims.next().is_some() {
            return Err(Failure::Unproven("tdx_claims_unavailable"));
        }
        let claims = normalized_claims(&claim, request, evaluation_time)
            .ok_or(Failure::Unproven("tdx_claims_unavailable"))?;
        if claims.debug
            || claims.tcb_status != "UpToDate"
            || claims.collateral_expiration_status != 0
        {
            return Err(Failure::Invalid("tdx_platform_policy"));
        }
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn collateral_is_unlinked_before_data_and_retained_for_proc_fd_reads() {
        use std::os::{fd::AsRawFd, unix::fs::MetadataExt};

        let file = anonymous_collateral(b"public-collateral").unwrap();
        assert_eq!(file.metadata().unwrap().nlink(), 0);
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
        let path = format!("/proc/self/fd/{}", file.as_raw_fd());
        assert_eq!(std::fs::read(&path).unwrap(), b"public-collateral");
        drop(file);
        assert!(std::fs::read(path).is_err());
    }

    fn request() -> TdxWorkerRequest {
        TdxWorkerRequest::new(
            b"{}".to_vec(),
            format!("{}{}", "07".repeat(48), "00".repeat(16)),
            "08".repeat(48),
            b"{}".to_vec(),
        )
        .unwrap()
    }

    fn claims() -> serde_json::Value {
        let request = request();
        json!({
            "quote":{"body":{
                "report_data":request.expected_report_data,
                "mr_config_id":request.expected_mr_config_id,
                "mr_td":"09".repeat(48),
                "rtmr_0":"0a".repeat(48),"rtmr_1":"0b".repeat(48),
                "rtmr_2":"0c".repeat(48),"rtmr_3":"0d".repeat(48),
                "td_attributes":"00".repeat(8),
            }},
            "report_data":request.expected_report_data,
            "init_data":request.expected_mr_config_id,
            "td_attributes":{"debug":false},
            "tcb_status":"UpToDate","collateral_expiration_status":"0",
        })
    }

    #[test]
    fn claims_are_normalized_from_the_actual_backend_shape() {
        let result = normalized_claims(&claims(), &request(), 123).unwrap();
        assert_eq!(result.rtmrs[0], "0a".repeat(48));
        assert!(!result.debug);
        assert_eq!(result.collateral_expiration_status, 0);
        assert_eq!(result.evaluation_time_unix_seconds, 123);
    }

    #[test]
    fn malformed_or_inconsistent_claims_cannot_be_returned_as_verified() {
        let mut value = claims();
        value["quote"]["body"]["mr_config_id"] = json!("09".repeat(48));
        assert!(normalized_claims(&value, &request(), 123).is_none());
        let mut value = claims();
        value["td_attributes"]["debug"] = json!(true);
        assert!(normalized_claims(&value, &request(), 123).is_none());
        let mut value = claims();
        value["quote"]["body"]["rtmr_3"] = json!("bad");
        assert!(normalized_claims(&value, &request(), 123).is_none());
        assert!(normalized_claims(&claims(), &request(), 0).is_none());
    }

    #[cfg(not(feature = "execution-quote-worker-tdx"))]
    #[test]
    fn feature_off_worker_can_only_return_unproven() {
        let request = request();
        let result = verify_request(&request).unwrap();
        assert_eq!(result.status, WorkerStatus::Unproven);
        assert!(result.claims.is_none());
        assert_eq!(result.request_sha384, request.sha384_hex().unwrap());
    }

    #[test]
    fn unsupported_execution_profile_is_rejected_before_hardware() {
        let mut request = request();
        request.expected_report_data = "07".repeat(64);
        let result = verify_request(&request).unwrap();
        assert_eq!(result.status, WorkerStatus::Invalid);
        assert!(result.claims.is_none());
    }
}
