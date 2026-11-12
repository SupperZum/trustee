// SPDX-License-Identifier: Apache-2.0
//! Historical bootstrap checking never accepts a live grant issuance request.
use execution_proof_verifier::{
    gcp_bootstrap_history::{GcpBootstrapHistoryRequest, GcpBootstrapHistoryResponse},
    gcp_worker_protocol::{GcpHardwareStatus, MAX_GCP_WORKER_REQUEST_BYTES},
};
use std::io::{Read, Write};

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("GCP bootstrap history worker protocol failed")]
pub struct WorkerProtocolError;

pub fn run_stdio() -> Result<(), WorkerProtocolError> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_GCP_WORKER_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| WorkerProtocolError)?;
    let request = GcpBootstrapHistoryRequest::decode(&input).map_err(|_| WorkerProtocolError)?;
    let response = verify_request(&request)?;
    std::io::stdout()
        .lock()
        .write_all(&response.encode().map_err(|_| WorkerProtocolError)?)
        .map_err(|_| WorkerProtocolError)
}
pub fn verify_request(
    request: &GcpBootstrapHistoryRequest,
) -> Result<GcpBootstrapHistoryResponse, WorkerProtocolError> {
    request.validate().map_err(|_| WorkerProtocolError)?;
    #[cfg(feature = "execution-quote-worker-tdx")]
    {
        use crate::gcp_execution_quote_worker::hardware::{
            verify_quote, Failure, QuoteCheckInputs,
        };
        let b = &request.bootstrap;
        let expected = b.derived_report_data().map_err(|_| WorkerProtocolError)?;
        let binding = b.boot_binding_sha384().map_err(|_| WorkerProtocolError)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|_| WorkerProtocolError)?;
        let checked = runtime.block_on(verify_quote(QuoteCheckInputs {
            quote: &b.evidence.tdx_quote,
            table: &b.evidence.ccel_table,
            log: &b.evidence.ccel_log,
            expected: &expected,
            boot_policy: &b.boot_policy,
            module_policy: &b.module_policy,
            collateral_json: &b.collateral_json,
            boot_binding_sha384: &binding,
        }));
        let (status, reason, facts) = match checked {
            Ok(facts) => (
                GcpHardwareStatus::Checked,
                "historical_bootstrap_hardware_checked",
                Some(facts),
            ),
            Err(Failure::Invalid(reason)) => (GcpHardwareStatus::Invalid, reason, None),
            Err(Failure::Unproven(reason)) => (GcpHardwareStatus::Unproven, reason, None),
        };
        GcpBootstrapHistoryResponse::new(request, status, reason, facts)
            .map_err(|_| WorkerProtocolError)
    }
    #[cfg(not(feature = "execution-quote-worker-tdx"))]
    GcpBootstrapHistoryResponse::new(
        request,
        GcpHardwareStatus::Unproven,
        "tdx_verifier_unavailable",
        None,
    )
    .map_err(|_| WorkerProtocolError)
}
