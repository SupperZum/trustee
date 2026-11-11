// SPDX-License-Identifier: Apache-2.0

//! Opt-in GCP launch quote and same-evaluation policy capture. The caller selects
//! independent boot/module policy and a fresh session nonce. This module proves
//! neither recorder/key origin nor producer isolation, enrollment, admission or
//! execution. The session owner separately checks time and key possession.
//! The GCP profile uses platform boot evidence in place of a generic MRCONFIGID check.

use crate::launch_policy::{evaluate_launch_policy, AsPolicyFacts, PolicyDecision};
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_contract::{
    gcp_boot_binding::GcpBootBindingV1, gcp_session::GcpLaunchEvidence, VerifiedLaunchGrant,
};
use execution_proof_verifier::{
    gcp_boot_evidence::{check_boot_evidence, GcpBootEvidencePolicy, StructuralBootEvidence},
    gcp_tdx_policy::{GcpTdxModuleFacts, GcpTdxModulePolicyV1},
};
use kbs_types::{Tee, TeePubKey};
use key_value_storage::StorageProvider;
use policy_engine::{rego::Regorus, PolicyEngine};
use serde_json::{json, Value};
use sha2::{Digest, Sha384};
use std::{fmt, sync::Arc};
use verifier::{InitDataHash, ReportData, Verifier, VerifierConfig};

pub const GCP_LAUNCH_QUOTE_PROFILE: &str = "onb17.gcp-launch-quote.v2";
pub const MAX_GCP_LAUNCH_RUNTIME_BYTES: usize = 16 * 1024;
const NONCE_DOMAIN: &[u8] = b"qlad.execution-proof.gcp-launch-quote-nonce.v2";

/// Redacted errors never include evidence, policy, keys or verifier payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcpLaunchEvidenceError {
    InvalidContext,
    InvalidRuntimeData,
    InvalidEvidence,
    InvalidBootEvidence,
    VerifierUnavailable,
    VerificationFailed,
    InvalidClaims,
    PolicyEvaluationFailed,
    PolicyDenied,
    PolicyHashMismatch,
}
impl fmt::Display for GcpLaunchEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidContext => "invalid GCP launch context",
            Self::InvalidRuntimeData => "invalid GCP launch runtime data",
            Self::InvalidEvidence => "invalid bounded GCP launch evidence",
            Self::InvalidBootEvidence => "GCP launch boot predicates failed",
            Self::VerifierUnavailable => "GCP TDX verifier unavailable",
            Self::VerificationFailed => "GCP launch quote verification failed",
            Self::InvalidClaims => "GCP authenticated quote facts differ",
            Self::PolicyEvaluationFailed => "GCP launch policy evaluation failed",
            Self::PolicyDenied => "GCP launch policy did not affirm the quote",
            Self::PolicyHashMismatch => "evaluated GCP policy differs from the grant",
        })
    }
}
impl std::error::Error for GcpLaunchEvidenceError {}

/// Immutable caller-selected expectations, not a freshness or boot capability.
/// No Deserialize or raw Debug implementation can manufacture a verified result.
#[derive(Clone)]
pub struct ExpectedGcpLaunchQuote {
    nonce: String,
    grant_digest: String,
    launch_policy_sha384: String,
    boot_binding: GcpBootBindingV1,
    boot_binding_sha384: String,
    canonical_runtime: Vec<u8>,
    report_data: [u8; 64],
    boot_policy: GcpBootEvidencePolicy,
    module_policy: GcpTdxModulePolicyV1,
}
impl ExpectedGcpLaunchQuote {
    pub fn new(
        grant: &VerifiedLaunchGrant,
        boot_binding: GcpBootBindingV1,
        server_random: [u8; 32],
        tee_pubkey: &TeePubKey,
        boot_policy: GcpBootEvidencePolicy,
        module_policy: GcpTdxModulePolicyV1,
    ) -> Result<Self, GcpLaunchEvidenceError> {
        let binding = boot_binding
            .digest_sha384()
            .map_err(|_| GcpLaunchEvidenceError::InvalidContext)?;
        if grant.binding().profile_sha384 != binding || server_random == [0; 32] {
            return Err(GcpLaunchEvidenceError::InvalidContext);
        }
        boot_policy
            .validate()
            .map_err(|_| GcpLaunchEvidenceError::InvalidContext)?;
        module_policy
            .validate()
            .map_err(|_| GcpLaunchEvidenceError::InvalidContext)?;
        let oversized = match tee_pubkey {
            TeePubKey::RSA { alg, k_mod, k_exp } => [alg, k_mod, k_exp]
                .iter()
                .any(|v| v.is_empty() || v.len() > 4096),
            TeePubKey::EC { crv, alg, x, y } => [crv, alg, x, y]
                .iter()
                .any(|v| v.is_empty() || v.len() > 4096),
        };
        if oversized {
            return Err(GcpLaunchEvidenceError::InvalidRuntimeData);
        }
        let raw_binding =
            hex::decode(&binding).map_err(|_| GcpLaunchEvidenceError::InvalidContext)?;
        let mut transcript = Vec::new();
        for field in [
            NONCE_DOMAIN,
            grant.grant_digest().as_bytes(),
            &server_random,
            &raw_binding,
        ] {
            transcript.extend_from_slice(&(field.len() as u64).to_be_bytes());
            transcript.extend_from_slice(field);
        }
        let nonce = format!("onb17-gcp-launch-v2:{}", hash(&transcript));
        let runtime = json!({"tee-pubkey":tee_pubkey,"nonce":nonce,"additional-evidence":""});
        let canonical_runtime = serde_json_canonicalizer::to_vec(&runtime)
            .map_err(|_| GcpLaunchEvidenceError::InvalidRuntimeData)?;
        if canonical_runtime.len() > MAX_GCP_LAUNCH_RUNTIME_BYTES {
            return Err(GcpLaunchEvidenceError::InvalidRuntimeData);
        }
        let mut report_data = [0; 64];
        report_data[..48].copy_from_slice(&Sha384::digest(&canonical_runtime));
        Ok(Self {
            nonce,
            grant_digest: grant.grant_digest().into(),
            launch_policy_sha384: grant.binding().launch_policy_sha384.clone(),
            boot_binding,
            boot_binding_sha384: binding,
            canonical_runtime,
            report_data,
            boot_policy,
            module_policy,
        })
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }
    pub fn boot_binding(&self) -> &GcpBootBindingV1 {
        &self.boot_binding
    }
    pub fn boot_binding_sha384(&self) -> &str {
        &self.boot_binding_sha384
    }
    pub fn report_data(&self) -> &[u8; 64] {
        &self.report_data
    }
    pub fn canonical_runtime(&self) -> &[u8] {
        &self.canonical_runtime
    }
    pub fn launch_policy_sha384(&self) -> &str {
        &self.launch_policy_sha384
    }
}

/// Constructed only after fixed TDX verification and independent boot predicates.
/// This result is not proof of a protected producer or an authorization object.
pub struct GcpVerifiedLaunchEvidence {
    expected: ExpectedGcpLaunchQuote,
    claims: Value,
    evidence_sha384: String,
}
impl GcpVerifiedLaunchEvidence {
    pub fn expected(&self) -> &ExpectedGcpLaunchQuote {
        &self.expected
    }
    pub fn claims(&self) -> &Value {
        &self.claims
    }
    pub fn evidence_sha384(&self) -> &str {
        &self.evidence_sha384
    }
}
/// Actual captured policy evaluation, without a session/credential/exec grant.
pub struct AppraisedGcpLaunch {
    evidence: GcpVerifiedLaunchEvidence,
    policy: AsPolicyFacts,
}
impl AppraisedGcpLaunch {
    pub fn evidence(&self) -> &GcpVerifiedLaunchEvidence {
        &self.evidence
    }
    pub fn policy(&self) -> &AsPolicyFacts {
        &self.policy
    }
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha384::digest(bytes))
}

fn checked_evidence(
    expected: &ExpectedGcpLaunchQuote,
    raw: &[u8],
) -> Result<(GcpLaunchEvidence, StructuralBootEvidence, String), GcpLaunchEvidenceError> {
    let evidence =
        GcpLaunchEvidence::decode(raw).map_err(|_| GcpLaunchEvidenceError::InvalidEvidence)?;
    let boot = check_boot_evidence(
        &evidence.ccel_table,
        &evidence.ccel_log,
        &evidence.tdx_quote,
        &expected.report_data,
        &expected.boot_policy,
    )
    .map_err(|_| GcpLaunchEvidenceError::InvalidBootEvidence)?;
    // Quote ABI v5 has service-TD fields outside this GCP profile.
    if boot.quote.quote_version != 4 {
        return Err(GcpLaunchEvidenceError::InvalidBootEvidence);
    }
    expected
        .module_policy
        .check_facts(&GcpTdxModuleFacts {
            mr_seam: hex::encode(boot.quote.mr_seam),
            td_attributes: boot.quote.td_attributes,
        })
        .map_err(|_| GcpLaunchEvidenceError::InvalidBootEvidence)?;
    Ok((evidence, boot, hash(raw)))
}

/// Fixed TDX dispatch; no public injected verifier or sample fallback. The caller
/// provides trusted collateral configuration/storage and separately limits I/O.
pub async fn verify_gcp_launch_quote(
    expected: ExpectedGcpLaunchQuote,
    evidence_json: &[u8],
    config: Option<VerifierConfig>,
    storage: Arc<dyn StorageProvider>,
) -> Result<GcpVerifiedLaunchEvidence, GcpLaunchEvidenceError> {
    let (evidence, boot, digest) = checked_evidence(&expected, evidence_json)?;
    let verifier = verifier::to_verifier(&Tee::Tdx, config, storage)
        .await
        .map_err(|_| GcpLaunchEvidenceError::VerifierUnavailable)?;
    verify_with(expected, evidence, boot, digest, verifier.as_ref()).await
}
async fn verify_with(
    expected: ExpectedGcpLaunchQuote,
    evidence: GcpLaunchEvidence,
    boot: StructuralBootEvidence,
    evidence_sha384: String,
    verifier: &(dyn Verifier + Send + Sync),
) -> Result<GcpVerifiedLaunchEvidence, GcpLaunchEvidenceError> {
    let claims = verifier
        .evaluate(
            json!({"quote":STANDARD.encode(&evidence.tdx_quote),"cc_eventlog":null}),
            &ReportData::Value(expected.report_data()),
            &InitDataHash::NotProvided,
        )
        .await
        .map_err(|_| GcpLaunchEvidenceError::VerificationFailed)?;
    let mut claims = claims.into_iter();
    let (claim, class) = claims.next().ok_or(GcpLaunchEvidenceError::InvalidClaims)?;
    if class != "cpu"
        || claims.next().is_some()
        || !verifier::gcp_execution_quote_worker::normalized_claims_match(&claim, &boot.quote)
    {
        return Err(GcpLaunchEvidenceError::InvalidClaims);
    }
    Ok(GcpVerifiedLaunchEvidence {
        expected,
        claims: claim,
        evidence_sha384,
    })
}

pub async fn appraise_gcp_launch_quote(
    expected: ExpectedGcpLaunchQuote,
    evidence_json: &[u8],
    config: Option<VerifierConfig>,
    storage: Arc<dyn StorageProvider>,
    engine: &PolicyEngine<Regorus>,
    policy_id: &str,
    reference_data: Option<&str>,
) -> Result<AppraisedGcpLaunch, GcpLaunchEvidenceError> {
    let evidence = verify_gcp_launch_quote(expected, evidence_json, config, storage).await?;
    appraise_verified(evidence, engine, policy_id, reference_data).await
}
async fn appraise_verified(
    evidence: GcpVerifiedLaunchEvidence,
    engine: &PolicyEngine<Regorus>,
    policy_id: &str,
    reference_data: Option<&str>,
) -> Result<AppraisedGcpLaunch, GcpLaunchEvidenceError> {
    let runtime: Value = serde_json::from_slice(evidence.expected.canonical_runtime())
        .map_err(|_| GcpLaunchEvidenceError::InvalidRuntimeData)?;
    let input = json!({"profile":GCP_LAUNCH_QUOTE_PROFILE,"tee":"tdx","tee_class":"cpu","grant_digest":evidence.expected.grant_digest(),"claims":evidence.claims,"runtime_data":runtime,"boot_binding":evidence.expected.boot_binding(),"boot_binding_sha384":evidence.expected.boot_binding_sha384(),"boot_policy":evidence.expected.boot_policy,"module_policy":evidence.expected.module_policy});
    let input = serde_json::to_string(&input).map_err(|_| GcpLaunchEvidenceError::InvalidClaims)?;
    let policy = evaluate_launch_policy(engine, policy_id, &input, reference_data)
        .await
        .map_err(|_| GcpLaunchEvidenceError::PolicyEvaluationFailed)?;
    if policy.capture().policy_commitment().sha384() != evidence.expected.launch_policy_sha384() {
        return Err(GcpLaunchEvidenceError::PolicyHashMismatch);
    }
    if policy.decision() != PolicyDecision::Accepted {
        return Err(GcpLaunchEvidenceError::PolicyDenied);
    }
    Ok(AppraisedGcpLaunch { evidence, policy })
}

#[cfg(test)]
#[path = "gcp_launch_evidence_tests.rs"]
mod tests;

/// Source-harness-only software seams; absent from normal AS builds.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod test_support {
    use super::*;
    pub(crate) fn evidence_bytes(expected: &ExpectedGcpLaunchQuote) -> Vec<u8> {
        super::tests::wire(expected)
    }
    pub(crate) async fn appraise_software(
        expected: ExpectedGcpLaunchQuote,
        raw: &[u8],
        engine: &PolicyEngine<Regorus>,
        policy: &str,
        references: Option<&str>,
    ) -> Result<AppraisedGcpLaunch, GcpLaunchEvidenceError> {
        let evidence = super::tests::software_verify(expected, raw, |_| {}, false).await?;
        super::appraise_verified(evidence, engine, policy, references).await
    }
}
