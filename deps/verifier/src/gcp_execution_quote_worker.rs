// SPDX-License-Identifier: Apache-2.0

//! Fixed GCP TDX quote and boot evidence checks. The parent verifies the
//! execution record, workflow and producer qualification before issuing a verdict.

use execution_proof_verifier::gcp_worker_protocol::{
    GcpHardwareRequest, GcpHardwareResponse, GcpHardwareStatus, MAX_GCP_WORKER_REQUEST_BYTES,
};
use std::io::{Read, Write};

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("GCP hardware worker protocol failed")]
pub struct WorkerProtocolError;

pub fn run_stdio() -> Result<(), WorkerProtocolError> {
    let mut input = Vec::new();
    std::io::stdin()
        .lock()
        .take(MAX_GCP_WORKER_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| WorkerProtocolError)?;
    let request = GcpHardwareRequest::decode(&input).map_err(|_| WorkerProtocolError)?;
    let response = verify_request(&request)?;
    std::io::stdout()
        .lock()
        .write_all(&response.encode().map_err(|_| WorkerProtocolError)?)
        .map_err(|_| WorkerProtocolError)
}

pub fn verify_request(
    request: &GcpHardwareRequest,
) -> Result<GcpHardwareResponse, WorkerProtocolError> {
    request.validate().map_err(|_| WorkerProtocolError)?;
    #[cfg(feature = "execution-quote-worker-tdx")]
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .map_err(|_| WorkerProtocolError)?;
        let (status, reason, facts) = match runtime.block_on(hardware::verify(request)) {
            Ok(facts) => (
                GcpHardwareStatus::Checked,
                "hardware_and_boot_predicates_checked",
                Some(facts),
            ),
            Err(hardware::Failure::Invalid(reason)) => (GcpHardwareStatus::Invalid, reason, None),
            Err(hardware::Failure::Unproven(reason)) => (GcpHardwareStatus::Unproven, reason, None),
        };
        GcpHardwareResponse::new(request, status, reason, facts).map_err(|_| WorkerProtocolError)
    }
    #[cfg(not(feature = "execution-quote-worker-tdx"))]
    GcpHardwareResponse::new(
        request,
        GcpHardwareStatus::Unproven,
        "tdx_verifier_unavailable",
        None,
    )
    .map_err(|_| WorkerProtocolError)
}

/// Compare data to the exact original quote fields. This predicate does not
/// authenticate either input; callers must obtain claims from fixed actual QVL.
pub fn normalized_claims_match(
    value: &serde_json::Value,
    raw: &execution_proof_verifier::gcp_boot_evidence::PublicQuoteFacts,
) -> bool {
    fn field(value: &serde_json::Value, pointer: &str, expected: &[u8]) -> bool {
        value
            .pointer(pointer)
            .and_then(|v| v.as_str())
            .and_then(|v| hex::decode(v).ok())
            .is_some_and(|v| v == expected)
    }
    for (path, expected) in [
        ("/quote/body/report_data", raw.report_data.as_slice()),
        ("/report_data", raw.report_data.as_slice()),
        ("/quote/body/mr_config_id", raw.mr_config_id.as_slice()),
        ("/init_data", raw.mr_config_id.as_slice()),
        ("/quote/body/mr_td", raw.mr_td.as_slice()),
        ("/quote/body/mr_owner", raw.mr_owner.as_slice()),
        ("/quote/body/mr_seam", raw.mr_seam.as_slice()),
        (
            "/quote/body/td_attributes",
            raw.td_attributes.to_le_bytes().as_slice(),
        ),
        ("/quote/body/rtmr_0", raw.rtmrs[0].as_slice()),
        ("/quote/body/rtmr_1", raw.rtmrs[1].as_slice()),
        ("/quote/body/rtmr_2", raw.rtmrs[2].as_slice()),
        ("/quote/body/rtmr_3", raw.rtmrs[3].as_slice()),
    ] {
        if !field(value, path, expected) {
            return false;
        }
    }
    value
        .pointer("/td_attributes/debug")
        .and_then(|v| v.as_bool())
        == Some(false)
        && value.get("tcb_status").and_then(|v| v.as_str()) == Some("UpToDate")
        && value
            .get("collateral_expiration_status")
            .and_then(|v| v.as_str())
            == Some("0")
}

#[cfg(feature = "execution-quote-worker-tdx")]
pub(crate) mod hardware {
    use super::*;
    use crate::{InitDataHash, ReportData, VerifierConfig};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use execution_proof_verifier::{
        gcp_boot_evidence::check_boot_evidence, gcp_tdx_policy::GcpTdxModuleFacts,
        gcp_worker_protocol::GcpHardwareFacts,
    };
    use key_value_storage::{KvStorageProvider, StorageBackendConfig};
    use std::{os::fd::AsRawFd, path::PathBuf, time::SystemTime};

    pub(crate) enum Failure {
        Invalid(&'static str),
        Unproven(&'static str),
    }

    pub(super) async fn verify(request: &GcpHardwareRequest) -> Result<GcpHardwareFacts, Failure> {
        let expected: [u8; 64] = hex::decode(&request.expected_report_data)
            .map_err(|_| Failure::Invalid("gcp_report_data"))?
            .try_into()
            .map_err(|_| Failure::Invalid("gcp_report_data"))?;
        verify_quote(QuoteCheckInputs {
            quote: &request.envelope.tdx_quote,
            table: &request.envelope.ccel_table,
            log: &request.envelope.ccel_log,
            expected: &expected,
            boot_policy: &request.boot_policy,
            module_policy: &request.module_policy,
            collateral_json: &request.collateral_json,
            boot_binding_sha384: &request.expected_boot_binding_sha384,
        })
        .await
    }

    /// Internal backend shared by separately validated protocol phases. Callers
    /// must compute expected REPORT_DATA from their complete typed transcript.
    pub(crate) struct QuoteCheckInputs<'a> {
        pub quote: &'a [u8],
        pub table: &'a [u8],
        pub log: &'a [u8],
        pub expected: &'a [u8; 64],
        pub boot_policy: &'a execution_proof_verifier::gcp_boot_evidence::GcpBootEvidencePolicy,
        pub module_policy: &'a execution_proof_verifier::gcp_tdx_policy::GcpTdxModulePolicyV1,
        pub collateral_json: &'a [u8],
        pub boot_binding_sha384: &'a str,
    }
    pub(crate) async fn verify_quote(
        input: QuoteCheckInputs<'_>,
    ) -> Result<GcpHardwareFacts, Failure> {
        let boot = check_boot_evidence(
            input.table,
            input.log,
            input.quote,
            input.expected,
            input.boot_policy,
        )
        .map_err(|_| Failure::Invalid("gcp_boot_evidence"))?;
        // This profile accepts quote ABI v4. ABI v5 adds fields such as MRSERVICETD
        // outside its boot predicates.
        if boot.quote.quote_version != 4 {
            return Err(Failure::Invalid("gcp_quote_abi_profile"));
        }
        input
            .module_policy
            .check_facts(&GcpTdxModuleFacts {
                mr_seam: hex::encode(boot.quote.mr_seam),
                td_attributes: boot.quote.td_attributes,
            })
            .map_err(|_| Failure::Invalid("gcp_module_attributes"))?;
        let _: crate::intel_dcap::collateral_service::PlatformCollaterals =
            execution_proof_verifier::schema::decode(input.collateral_json, 4 << 20)
                .map_err(|_| Failure::Invalid("gcp_collateral_schema"))?;
        let collateral = crate::execution_quote_worker::anonymous_collateral(input.collateral_json)
            .map_err(|_| Failure::Unproven("collateral_staging_unavailable"))?;
        let url = url::Url::from_file_path(PathBuf::from(format!(
            "/proc/self/fd/{}",
            collateral.as_raw_fd()
        )))
        .map_err(|_| Failure::Unproven("collateral_staging_unavailable"))?;
        let config: VerifierConfig = serde_json::from_value(serde_json::json!({
            "dcap_verifier":{"collateral_service":url.as_str(),"tcb_update_type":"early"}
        }))
        .map_err(|_| Failure::Unproven("tdx_configuration_unavailable"))?;
        let selected = config
            .dcap_verifier
            .as_ref()
            .ok_or(Failure::Unproven("tdx_configuration_unavailable"))?;
        if serde_json::to_value(selected)
            .ok()
            .as_ref()
            .and_then(|v| v.get("collateral_service"))
            .and_then(|v| v.as_str())
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
        let before = SystemTime::now();
        // Original raw quote, including explicitly supported GCP zero padding,
        // goes to QVL unchanged. CCEL is mandatory above, not skipped: the
        // private GCP parser owns the stricter framing and boot recipe checks.
        let claims = verifier
            .evaluate(
                serde_json::json!({
                    "quote": STANDARD.encode(input.quote), "cc_eventlog":null
                }),
                &ReportData::Value(input.expected),
                &InitDataHash::NotProvided,
            )
            .await
            .map_err(|_| Failure::Unproven("tdx_verification_failed"))?;
        drop(collateral);
        let after = SystemTime::now();
        if after
            .duration_since(before)
            .map_or(true, |d| d.as_secs() > 30)
        {
            return Err(Failure::Unproven("verification_clock_unavailable"));
        }
        let mut claims = claims.into_iter();
        let (claim, class) = claims
            .next()
            .ok_or(Failure::Unproven("tdx_claims_unavailable"))?;
        if class != "cpu"
            || claims.next().is_some()
            || !normalized_claims_match(&claim, &boot.quote)
        {
            return Err(Failure::Invalid("tdx_authenticated_fact_mismatch"));
        }
        let q = boot.quote;
        Ok(GcpHardwareFacts {
            quote_sha384: hex::encode(q.quote_sha384),
            report_data: hex::encode(q.report_data),
            boot_binding_sha384: input.boot_binding_sha384.into(),
            mr_config_id: hex::encode(q.mr_config_id),
            mr_td: hex::encode(q.mr_td),
            mr_owner: hex::encode(q.mr_owner),
            mr_seam: hex::encode(q.mr_seam),
            td_attributes: q.td_attributes,
            rtmrs: q.rtmrs.map(hex::encode),
            event_count: boot.event_count,
            evaluation_time_unix_seconds: after
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_err(|_| Failure::Unproven("verification_clock_unavailable"))?
                .as_secs(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use execution_proof_verifier::gcp_boot_evidence::PublicQuoteFacts;

    fn request() -> GcpHardwareRequest {
        GcpHardwareRequest::decode(include_bytes!(
            "../tests/fixtures/gcp-worker-software-request.json"
        ))
        .unwrap()
    }
    #[test]
    fn invalid_record_transcript_never_reaches_hardware() {
        let mut request = request();
        request.record.task.generation += 1;
        assert!(verify_request(&request).is_err());
    }
    #[test]
    fn backend_unavailable_or_malformed_quote_never_returns_checked() {
        let result = verify_request(&request()).unwrap();
        #[cfg(not(feature = "execution-quote-worker-tdx"))]
        assert_eq!(result.status, GcpHardwareStatus::Unproven);
        #[cfg(feature = "execution-quote-worker-tdx")]
        assert_eq!(result.status, GcpHardwareStatus::Invalid);
        assert!(result.facts.is_none());
    }
    #[test]
    fn normalized_authenticated_claims_must_equal_every_raw_field() {
        let facts = PublicQuoteFacts {
            quote_version: 4,
            mr_td: [1; 48],
            mr_config_id: [0; 48],
            mr_owner: [2; 48],
            mr_seam: [3; 48],
            td_attributes: 1 << 28,
            rtmrs: [[4; 48]; 4],
            report_data: [5; 64],
            quote_sha384: [6; 48],
            declared_frame_bytes: 4935,
            trailing_zero_padding_bytes: 3065,
        };
        let mut value = serde_json::json!({"quote":{"body":{
            "report_data":hex::encode(facts.report_data),"mr_config_id":hex::encode(facts.mr_config_id),
            "mr_td":hex::encode(facts.mr_td),"mr_owner":hex::encode(facts.mr_owner),
            "mr_seam":hex::encode(facts.mr_seam),"td_attributes":hex::encode(facts.td_attributes.to_le_bytes()),
            "rtmr_0":hex::encode(facts.rtmrs[0]),"rtmr_1":hex::encode(facts.rtmrs[1]),
            "rtmr_2":hex::encode(facts.rtmrs[2]),"rtmr_3":hex::encode(facts.rtmrs[3])}},
            "report_data":hex::encode(facts.report_data),"init_data":hex::encode(facts.mr_config_id),
            "td_attributes":{"debug":false},"tcb_status":"UpToDate","collateral_expiration_status":"0"});
        assert!(normalized_claims_match(&value, &facts));
        for pointer in [
            "/quote/body/report_data",
            "/report_data",
            "/quote/body/mr_config_id",
            "/init_data",
            "/quote/body/mr_td",
            "/quote/body/mr_owner",
            "/quote/body/mr_seam",
            "/quote/body/td_attributes",
            "/quote/body/rtmr_0",
            "/quote/body/rtmr_1",
            "/quote/body/rtmr_2",
            "/quote/body/rtmr_3",
            "/tcb_status",
            "/collateral_expiration_status",
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = serde_json::json!("bad");
            assert!(!normalized_claims_match(&changed, &facts), "{pointer}");
        }
        value["td_attributes"]["debug"] = serde_json::json!(true);
        assert!(!normalized_claims_match(&value, &facts));
    }
    /// Diagnostic public-challenge evidence exercises the real QVL+boot backend
    /// only. It MUST fail the outer protected-R transcript contract.
    #[cfg(feature = "execution-quote-worker-tdx")]
    #[test]
    #[ignore = "requires Intel QVL and unexpired collateral for the retained quote"]
    fn retained_crypto_boot_backend_cannot_authorize_a_diagnostic_record() {
        use execution_proof_verifier::gcp_boot_evidence::{
            GcpBootEvidencePolicy, GcpInstanceIdentity, QuotePaddingPolicy,
        };
        let mut request = request();
        request.envelope.tdx_quote = include_bytes!("../../../../execution-proof-prototype/verifier/tests/fixtures/gcp_boot_v1/baseline-quote.bin").to_vec();
        request.envelope.ccel_table = include_bytes!("../../../../execution-proof-prototype/verifier/tests/fixtures/gcp_boot_v1/baseline-acpi-ccel.bin").to_vec();
        request.envelope.ccel_log = include_bytes!("../../../../execution-proof-prototype/verifier/tests/fixtures/gcp_boot_v1/baseline-ccel.bin").to_vec();
        request.expected_report_data = hex::encode(include_bytes!("../../../../execution-proof-prototype/verifier/tests/fixtures/gcp_boot_v1/baseline-host-challenge.bin"));
        request.collateral_json =
            include_bytes!("../tests/fixtures/gcp-public-collateral.json").to_vec();
        request.boot_policy = GcpBootEvidencePolicy {
            expected_pe_sha384:"c4240c5a835ca1c7b6b9c3dd762477870ba5b7a295ec0f551eb45d442be8926b3d887ea59fa348ff5e8832aaf595c8b4".into(),
            expected_firmware_mrtd:"f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3".into(),
            expected_instance:GcpInstanceIdentity {instance_id:1159420029374854386,
                numerical_project_id:876967775446,zone:"us-central1-a".into()},
            quote_padding:QuotePaddingPolicy::GcpTsmZeroPadded8000,
        };
        assert!(
            verify_request(&request).is_err(),
            "diagnostic is not a protected R quote"
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        // Internal backend unit seam, not the public worker contract. It does
        // not mint a response/producer/exec verdict for the diagnostic challenge.
        let facts = runtime
            .block_on(hardware::verify(&request))
            .unwrap_or_else(|_| panic!("retained QVL/boot backend failed"));
        assert_eq!(facts.mr_config_id, "00".repeat(48));
        assert_eq!(facts.event_count, 22);
        assert_eq!(facts.report_data, request.expected_report_data);
        let mut v5 = request.clone();
        v5.envelope.tdx_quote[..2].copy_from_slice(&5u16.to_le_bytes());
        v5.envelope.tdx_quote.splice(48..48, [2, 0, 0x48, 2, 0, 0]);
        v5.envelope.tdx_quote.truncate(8000);
        assert!(
            matches!(
                runtime.block_on(hardware::verify(&v5)),
                Err(hardware::Failure::Invalid("gcp_quote_abi_profile"))
            ),
            "v5 needs independent service-TD/profile qualification"
        );
        let mut bad = request.clone();
        bad.envelope.tdx_quote[632] ^= 1;
        assert!(
            runtime.block_on(hardware::verify(&bad)).is_err(),
            "signature mutation"
        );
        bad = request;
        bad.expected_report_data.replace_range(126.., "01");
        assert!(
            runtime.block_on(hardware::verify(&bad)).is_err(),
            "full64 tail mutation"
        );
    }
}
