// SPDX-License-Identifier: Apache-2.0
//! Fixed pre-grant hardware checks. A result is not issuer admission, key
//! custody/producer qualification, or a replacement for consuming pending state.

use execution_proof_verifier::{
    gcp_pregrant_protocol::{GcpPregrantRequest, GcpPregrantResponse},
    gcp_worker_protocol::{GcpHardwareStatus, MAX_GCP_WORKER_REQUEST_BYTES},
};
use std::io::{Read, Write};

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("GCP pre-grant worker protocol failed")]
pub struct WorkerProtocolError;

fn now() -> Result<u64, WorkerProtocolError> {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| WorkerProtocolError)
}
pub fn run_stdio() -> Result<(), WorkerProtocolError> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_GCP_WORKER_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| WorkerProtocolError)?;
    let request = GcpPregrantRequest::decode(&input).map_err(|_| WorkerProtocolError)?;
    let response = verify_request(&request)?;
    std::io::stdout()
        .lock()
        .write_all(&response.encode().map_err(|_| WorkerProtocolError)?)
        .map_err(|_| WorkerProtocolError)
}
pub fn verify_request(
    request: &GcpPregrantRequest,
) -> Result<GcpPregrantResponse, WorkerProtocolError> {
    request.validate().map_err(|_| WorkerProtocolError)?;
    if request.verify_authority(now()?).is_err() {
        return GcpPregrantResponse::new(
            request,
            GcpHardwareStatus::Invalid,
            "gcp_pregrant_authority",
            None,
        )
        .map_err(|_| WorkerProtocolError);
    }
    #[cfg(feature = "execution-quote-worker-tdx")]
    {
        use crate::gcp_execution_quote_worker::hardware::{
            verify_quote, Failure, QuoteCheckInputs,
        };
        let expected = request
            .derived_report_data()
            .map_err(|_| WorkerProtocolError)?;
        let binding = request
            .boot_binding_sha384()
            .map_err(|_| WorkerProtocolError)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|_| WorkerProtocolError)?;
        let checked = runtime.block_on(verify_quote(QuoteCheckInputs {
            quote: &request.evidence.tdx_quote,
            table: &request.evidence.ccel_table,
            log: &request.evidence.ccel_log,
            expected: &expected,
            boot_policy: &request.boot_policy,
            module_policy: &request.module_policy,
            collateral_json: &request.collateral_json,
            boot_binding_sha384: &binding,
        }));
        let (status, reason, facts) = match checked {
            Ok(facts) => (
                GcpHardwareStatus::Checked,
                "pregrant_hardware_and_boot_checked",
                Some(facts),
            ),
            Err(Failure::Invalid(reason)) => (GcpHardwareStatus::Invalid, reason, None),
            Err(Failure::Unproven(reason)) => (GcpHardwareStatus::Unproven, reason, None),
        };
        if request.verify_authority(now()?).is_err() {
            return GcpPregrantResponse::new(
                request,
                GcpHardwareStatus::Invalid,
                "gcp_pregrant_authority_expired",
                None,
            )
            .map_err(|_| WorkerProtocolError);
        }
        GcpPregrantResponse::new(request, status, reason, facts).map_err(|_| WorkerProtocolError)
    }
    #[cfg(not(feature = "execution-quote-worker-tdx"))]
    GcpPregrantResponse::new(
        request,
        GcpHardwareStatus::Unproven,
        "tdx_verifier_unavailable",
        None,
    )
    .map_err(|_| WorkerProtocolError)
}
