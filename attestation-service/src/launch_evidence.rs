// SPDX-License-Identifier: Apache-2.0

//! Opt-in TDX quote binding and captured launch-policy evaluation.
//!
//! The public path uses the TDX verifier with mandatory expected REPORT_DATA
//! and MRCONFIGID. The surrounding session protocol must check current time
//! and recorder key possession. This module creates no session, EAR/appraisal,
//! resource authorization, or execution permission. Recheck grant validity
//! before admitting each new operation.

use crate::launch_policy::{evaluate_launch_policy, AsPolicyFacts, PolicyDecision};
use execution_proof_contract::VerifiedLaunchGrant;
use kbs_types::{Tee, TeePubKey};
use key_value_storage::StorageProvider;
use policy_engine::{rego::Regorus, PolicyEngine};
use serde_json::{json, Value};
use sha2::{Digest, Sha384};
use std::{fmt, sync::Arc};
use verifier::{InitDataHash, ReportData, Verifier, VerifierConfig};

pub const MAX_LAUNCH_EVIDENCE_BYTES: usize = 1024 * 1024;
pub const MAX_LAUNCH_RUNTIME_BYTES: usize = 16 * 1024;
pub const LAUNCH_QUOTE_PROFILE: &str = "onb17.launch-quote.v1";
const NONCE_DOMAIN: &[u8] = b"qlad.execution-proof.tdx-quote-nonce.v1";

/// Redacted failures: no submitted evidence, policy, or verifier error payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchEvidenceError {
    InvalidRuntimeData,
    EvidenceBounds,
    InvalidEvidence,
    VerifierUnavailable,
    VerificationFailed,
    InvalidClaims,
    PolicyEvaluationFailed,
    PolicyDenied,
    PolicyHashMismatch,
}

impl fmt::Display for LaunchEvidenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRuntimeData => "invalid launch runtime context",
            Self::EvidenceBounds => "launch evidence exceeds the input bound",
            Self::InvalidEvidence => "invalid launch evidence JSON object",
            Self::VerifierUnavailable => "TDX verifier unavailable",
            Self::VerificationFailed => "launch quote verification failed",
            Self::InvalidClaims => "launch quote requires one nonempty CPU claim object",
            Self::PolicyEvaluationFailed => "launch policy evaluation failed",
            Self::PolicyDenied => "launch policy did not affirm the quote",
            Self::PolicyHashMismatch => "evaluated launch policy differs from the grant",
        })
    }
}

impl std::error::Error for LaunchEvidenceError {}

/// Owned expected context, not an attestation result or a freshness capability.
/// Cloning preserves the same nonce; it never creates another authorization.
/// No raw Debug or deserialization is provided.
#[derive(Clone)]
pub struct ExpectedLaunchQuote {
    nonce: String,
    grant_digest: String,
    launch_policy_sha384: String,
    canonical_runtime: Vec<u8>,
    report_data: [u8; 48],
    init_data: [u8; 48],
}

impl ExpectedLaunchQuote {
    /// The session owner supplies a fresh CSPRNG value and a trusted expected
    /// MRCONFIGID. The typed key is bound as runtime data; this constructor does
    /// not prove key possession or that it is the grant's Ed25519 recorder key.
    pub fn new(
        grant: &VerifiedLaunchGrant,
        server_random: [u8; 32],
        tee_pubkey: &TeePubKey,
        expected_init_data_sha384: [u8; 48],
    ) -> Result<Self, LaunchEvidenceError> {
        // Bound caller-owned key strings before allocating a JSON copy.
        let oversized_key = match tee_pubkey {
            TeePubKey::RSA { alg, k_mod, k_exp } => {
                [alg, k_mod, k_exp].iter().any(|field| field.len() > 4096)
            }
            TeePubKey::EC { crv, alg, x, y } => {
                [crv, alg, x, y].iter().any(|field| field.len() > 4096)
            }
        };
        if oversized_key {
            return Err(LaunchEvidenceError::InvalidRuntimeData);
        }

        let mut nonce_material = Vec::new();
        for field in [
            NONCE_DOMAIN,
            grant.grant_digest().as_bytes(),
            &server_random,
            &expected_init_data_sha384,
        ] {
            nonce_material.extend_from_slice(&(field.len() as u64).to_be_bytes());
            nonce_material.extend_from_slice(field);
        }
        let nonce = format!("onb17-launch-v1:{}", hash_hex(&nonce_material));
        // Match the guest-components primary-attester wire transcript when
        // additional evidence is empty. Adding a JSON field would change it.
        let runtime = json!({
            "tee-pubkey": tee_pubkey,
            "nonce": nonce,
            "additional-evidence": "",
        });
        let canonical_runtime = serde_json_canonicalizer::to_vec(&runtime)
            .map_err(|_| LaunchEvidenceError::InvalidRuntimeData)?;
        if canonical_runtime.len() > MAX_LAUNCH_RUNTIME_BYTES {
            return Err(LaunchEvidenceError::InvalidRuntimeData);
        }
        let report_data = Sha384::digest(&canonical_runtime).into();
        Ok(Self {
            nonce,
            grant_digest: grant.grant_digest().into(),
            launch_policy_sha384: grant.binding().launch_policy_sha384.clone(),
            canonical_runtime,
            report_data,
            init_data: expected_init_data_sha384,
        })
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }
    pub fn report_data(&self) -> &[u8; 48] {
        &self.report_data
    }
    pub fn canonical_runtime(&self) -> &[u8] {
        &self.canonical_runtime
    }
    pub fn init_data(&self) -> &[u8; 48] {
        &self.init_data
    }
    pub fn launch_policy_sha384(&self) -> &str {
        &self.launch_policy_sha384
    }
}

/// Verifier output and the required server context used for that call.
/// This is neither a signed appraisal nor a public constructor for claims JSON.
pub struct VerifiedLaunchEvidence {
    expected: ExpectedLaunchQuote,
    claims: Value,
    evidence_sha384: String,
}

impl VerifiedLaunchEvidence {
    pub fn expected(&self) -> &ExpectedLaunchQuote {
        &self.expected
    }
    pub fn claims(&self) -> &Value {
        &self.claims
    }
    /// SHA384 of the exact received JSON bytes, including their whitespace.
    pub fn evidence_sha384(&self) -> &str {
        &self.evidence_sha384
    }
}

/// Verified quote plus one strict affirming evaluation of the grant-bound policy.
/// No bearer token, resource credential, release receipt, or execution is implied.
pub struct AppraisedLaunch {
    evidence: VerifiedLaunchEvidence,
    policy: AsPolicyFacts,
}

impl AppraisedLaunch {
    pub fn evidence(&self) -> &VerifiedLaunchEvidence {
        &self.evidence
    }
    pub fn policy(&self) -> &AsPolicyFacts {
        &self.policy
    }
}

fn hash_hex(bytes: &[u8]) -> String {
    hex::encode(Sha384::digest(bytes))
}

fn parse_evidence(evidence_json: &[u8]) -> Result<(Value, String), LaunchEvidenceError> {
    if evidence_json.len() > MAX_LAUNCH_EVIDENCE_BYTES {
        return Err(LaunchEvidenceError::EvidenceBounds);
    }
    let value: Value =
        serde_json::from_slice(evidence_json).map_err(|_| LaunchEvidenceError::InvalidEvidence)?;
    if !value.is_object() {
        return Err(LaunchEvidenceError::InvalidEvidence);
    }
    Ok((value, hash_hex(evidence_json)))
}

/// Verify a single primary TDX quote with mandatory report and init-data checks.
/// Verifier selection is fixed here; unavailable TDX support fails closed.
pub async fn verify_launch_quote(
    expected: ExpectedLaunchQuote,
    evidence_json: &[u8],
    verifier_config: Option<VerifierConfig>,
    storage: Arc<dyn StorageProvider>,
) -> Result<VerifiedLaunchEvidence, LaunchEvidenceError> {
    // Reject malformed/oversized input before constructing a verifier.
    let (evidence, evidence_sha384) = parse_evidence(evidence_json)?;
    let verifier = verifier::to_verifier(&Tee::Tdx, verifier_config, storage)
        .await
        .map_err(|_| LaunchEvidenceError::VerifierUnavailable)?;
    verify_with(expected, evidence, evidence_sha384, verifier.as_ref()).await
}

// Only private software tests can substitute a Verifier implementation.
// Public callers always use TDX dispatch.
async fn verify_with(
    expected: ExpectedLaunchQuote,
    evidence: Value,
    evidence_sha384: String,
    verifier: &(dyn Verifier + Send + Sync),
) -> Result<VerifiedLaunchEvidence, LaunchEvidenceError> {
    let claims = verifier
        .evaluate(
            evidence,
            &ReportData::Value(expected.report_data()),
            &InitDataHash::Value(expected.init_data()),
        )
        .await
        .map_err(|_| LaunchEvidenceError::VerificationFailed)?;
    let mut claims = claims.into_iter();
    let (claim, class) = claims.next().ok_or(LaunchEvidenceError::InvalidClaims)?;
    if claims.next().is_some()
        || class != "cpu"
        || !claim.as_object().is_some_and(|object| !object.is_empty())
    {
        return Err(LaunchEvidenceError::InvalidClaims);
    }
    Ok(VerifiedLaunchEvidence {
        expected,
        claims: claim,
        evidence_sha384,
    })
}

/// Verify the quote, then capture a strict affirming grant-bound launch policy.
/// Static references are caller-selected immutable data, not authenticated RVPS.
pub async fn appraise_launch_quote(
    expected: ExpectedLaunchQuote,
    evidence_json: &[u8],
    verifier_config: Option<VerifierConfig>,
    storage: Arc<dyn StorageProvider>,
    engine: &PolicyEngine<Regorus>,
    selected_policy_id: &str,
    reference_data: Option<&str>,
) -> Result<AppraisedLaunch, LaunchEvidenceError> {
    let evidence = verify_launch_quote(expected, evidence_json, verifier_config, storage).await?;
    appraise_verified(evidence, engine, selected_policy_id, reference_data).await
}

async fn appraise_verified(
    evidence: VerifiedLaunchEvidence,
    engine: &PolicyEngine<Regorus>,
    selected_policy_id: &str,
    reference_data: Option<&str>,
) -> Result<AppraisedLaunch, LaunchEvidenceError> {
    let runtime_data: Value = serde_json::from_slice(evidence.expected.canonical_runtime())
        .map_err(|_| LaunchEvidenceError::InvalidRuntimeData)?;
    let input = json!({
        "profile": LAUNCH_QUOTE_PROFILE,
        "tee": "tdx",
        "tee_class": "cpu",
        "grant_digest": evidence.expected.grant_digest(),
        "claims": evidence.claims,
        "runtime_data": runtime_data,
        "init_data_sha384": hex::encode(evidence.expected.init_data()),
    });
    let input = serde_json::to_string(&input).map_err(|_| LaunchEvidenceError::InvalidClaims)?;
    let policy = evaluate_launch_policy(engine, selected_policy_id, &input, reference_data)
        .await
        .map_err(|_| LaunchEvidenceError::PolicyEvaluationFailed)?;
    if policy.capture().policy_commitment().sha384() != evidence.expected.launch_policy_sha384() {
        return Err(LaunchEvidenceError::PolicyHashMismatch);
    }
    if policy.decision() != PolicyDecision::Accepted {
        return Err(LaunchEvidenceError::PolicyDenied);
    }
    Ok(AppraisedLaunch { evidence, policy })
}

/// Test-only software verifier support, excluded from normal builds.
/// Caller-supplied claims cannot construct verified or appraised objects.
#[cfg(test)]
#[allow(
    dead_code,
    reason = "software-only cross-component test support is unused in AS-only unit targets"
)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn evidence_bytes(expected: &ExpectedLaunchQuote) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "software_only": true,
            "report": hex::encode(expected.report_data()),
            "init": hex::encode(expected.init_data()),
        }))
        .expect("software fixture serialization")
    }

    pub(crate) struct SoftwareVerifier;

    #[async_trait::async_trait]
    impl Verifier for SoftwareVerifier {
        async fn evaluate(
            &self,
            evidence: Value,
            report: &ReportData,
            init: &InitDataHash,
        ) -> anyhow::Result<Vec<(Value, String)>> {
            let (ReportData::Value(report), InitDataHash::Value(init)) = (report, init) else {
                anyhow::bail!("software fixture requires both binding checks");
            };
            if evidence.get("software_only") != Some(&Value::Bool(true))
                || evidence.get("report") != Some(&Value::String(hex::encode(report)))
                || evidence.get("init") != Some(&Value::String(hex::encode(init)))
            {
                anyhow::bail!("software fixture binding mismatch");
            }
            Ok(vec![(json!({"software_only": true}), "cpu".into())])
        }
    }

    pub(crate) async fn appraise_with_verifier(
        expected: ExpectedLaunchQuote,
        wire: &[u8],
        verifier: &(dyn Verifier + Send + Sync),
        engine: &PolicyEngine<Regorus>,
        policy_id: &str,
        references: Option<&str>,
    ) -> Result<AppraisedLaunch, LaunchEvidenceError> {
        let (evidence, evidence_sha384) = parse_evidence(wire)?;
        let verified = verify_with(expected, evidence, evidence_sha384, verifier).await?;
        appraise_verified(verified, engine, policy_id, references).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use execution_proof_contract::{
        verify_launch_grant, GrantExpectations, LaunchBinding, LaunchGrant, Signed, ValidityWindow,
        GRANT_PURPOSE, VERSION,
    };
    use key_value_storage::memory::MemoryKeyValueStorage;
    use ring::{
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    const AFFIRM: &str = "package policy\nimport rego.v1\nlaunch_accepted if { input.profile == \"onb17.launch-quote.v1\"; input.claims.software_only == true; input.runtime_data.nonce != \"\"; data.reference == \"fixture\" }\ntrust_claims := {}\nextensions := []\n";

    fn grant(policy: &str, attempt: &str) -> VerifiedLaunchGrant {
        let key = Ed25519KeyPair::from_pkcs8(
            Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let grant = LaunchGrant {
            version: VERSION,
            purpose: GRANT_PURPOSE.into(),
            audience: "software-unit-fixture".into(),
            proof_required: true,
            grant_id: "grant-1".into(),
            validity: ValidityWindow {
                not_before: 10,
                expires: 20,
            },
            binding: LaunchBinding {
                authority: "authority".into(),
                tenant: "tenant".into(),
                workload_id: "workload".into(),
                container_role: "application-init".into(),
                attempt_id: attempt.into(),
                boot_id: "boot".into(),
                channel_key_sha384: "11".repeat(48),
                bootstrap_context_sha384: "12".repeat(48),
                selected_manifest_sha256: "13".repeat(32),
                effective_launch_sha384: "14".repeat(48),
                profile_sha384: "15".repeat(48),
                launch_policy_sha384: hash_hex(policy.as_bytes()),
                image_policy_sha384: "16".repeat(48),
                challenge_sha384: "17".repeat(48),
            },
        };
        let expected = GrantExpectations {
            authority_public_key: key.public_key().as_ref().try_into().unwrap(),
            audience: grant.audience.clone(),
            authority: grant.binding.authority.clone(),
            tenant: grant.binding.tenant.clone(),
            profile_sha384: grant.binding.profile_sha384.clone(),
            launch_policy_sha384: grant.binding.launch_policy_sha384.clone(),
            image_policy_sha384: grant.binding.image_policy_sha384.clone(),
        };
        let signature = hex::encode(key.sign(&grant.signing_bytes().unwrap()).as_ref());
        let wire = serde_json::to_vec(&Signed {
            statement: grant,
            signature,
        })
        .unwrap();
        verify_launch_grant(&wire, &expected, 10).unwrap()
    }

    fn key() -> TeePubKey {
        // This fixture covers wire shape only; it uses no encryption or key possession.
        TeePubKey::RSA {
            alg: "RSA-OAEP-256".into(),
            k_mod: "AQID".into(),
            k_exp: "AQAB".into(),
        }
    }

    fn expected(policy: &str) -> ExpectedLaunchQuote {
        ExpectedLaunchQuote::new(&grant(policy, "attempt"), [7; 32], &key(), [8; 48]).unwrap()
    }

    /// Private software-only fixture. It checks both required arguments and
    /// rejects changed binding bytes; it supplies no hardware/DCAP evidence.
    struct SoftwareOnlyVerifier {
        claims: Vec<(Value, String)>,
    }

    #[async_trait]
    impl Verifier for SoftwareOnlyVerifier {
        async fn evaluate(
            &self,
            evidence: Value,
            report: &ReportData,
            init: &InitDataHash,
        ) -> anyhow::Result<Vec<(Value, String)>> {
            let (ReportData::Value(report), InitDataHash::Value(init)) = (report, init) else {
                anyhow::bail!("software fixture requires both binding checks");
            };
            if evidence.get("software_only") != Some(&Value::Bool(true))
                || evidence.get("report") != Some(&Value::String(hex::encode(report)))
                || evidence.get("init") != Some(&Value::String(hex::encode(init)))
            {
                anyhow::bail!("confidential-software-fixture-marker");
            }
            Ok(self.claims.clone())
        }
    }

    fn software_verifier() -> SoftwareOnlyVerifier {
        SoftwareOnlyVerifier {
            claims: vec![(json!({"software_only": true}), "cpu".into())],
        }
    }

    fn software_wire(expected: &ExpectedLaunchQuote) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "software_only": true,
            "report": hex::encode(expected.report_data()),
            "init": hex::encode(expected.init_data()),
        }))
        .unwrap()
    }

    async fn software_verify(
        expected: ExpectedLaunchQuote,
        wire: &[u8],
        verifier: &SoftwareOnlyVerifier,
    ) -> Result<VerifiedLaunchEvidence, LaunchEvidenceError> {
        let (evidence, digest) = parse_evidence(wire)?;
        verify_with(expected, evidence, digest, verifier).await
    }

    #[test]
    fn expected_runtime_matches_legacy_empty_device_transcript_and_binds_context() {
        let grant = grant(AFFIRM, "attempt");
        let first = ExpectedLaunchQuote::new(&grant, [7; 32], &key(), [8; 48]).unwrap();
        let wire_runtime = json!({
            "tee-pubkey": key(), "nonce": first.nonce(), "additional-evidence": "",
        });
        assert_eq!(
            first.canonical_runtime(),
            serde_json_canonicalizer::to_vec(&wire_runtime).unwrap()
        );
        assert_eq!(
            first.report_data().as_slice(),
            Sha384::digest(first.canonical_runtime()).as_slice()
        );
        assert!(first.nonce().is_ascii() && first.nonce().len() <= 256);
        assert_eq!(first.grant_digest(), grant.grant_digest());
        assert_eq!(first.nonce(), first.clone().nonce());
        assert_ne!(
            first.nonce(),
            ExpectedLaunchQuote::new(&grant, [9; 32], &key(), [8; 48])
                .unwrap()
                .nonce()
        );
        assert_ne!(
            first.nonce(),
            ExpectedLaunchQuote::new(&grant, [7; 32], &key(), [9; 48])
                .unwrap()
                .nonce()
        );
        let other = super::tests::grant(AFFIRM, "other-attempt");
        assert_ne!(
            first.nonce(),
            ExpectedLaunchQuote::new(&other, [7; 32], &key(), [8; 48])
                .unwrap()
                .nonce()
        );
        let mut other_key = key();
        if let TeePubKey::RSA { k_mod, .. } = &mut other_key {
            *k_mod = "BAUG".into();
        }
        let changed_key = ExpectedLaunchQuote::new(&grant, [7; 32], &other_key, [8; 48]).unwrap();
        assert_ne!(first.report_data(), changed_key.report_data());
    }

    #[test]
    fn malformed_and_oversized_inputs_fail_with_redacted_errors() {
        assert_eq!(
            parse_evidence(&vec![b' '; MAX_LAUNCH_EVIDENCE_BYTES + 1]).err(),
            Some(LaunchEvidenceError::EvidenceBounds)
        );
        for wire in [b"[]".as_slice(), b"null", b"{secret-marker"] {
            let error = parse_evidence(wire).err().unwrap();
            assert_eq!(error, LaunchEvidenceError::InvalidEvidence);
            assert!(!format!("{error:?} {error}").contains("secret-marker"));
        }
        let mut oversized = key();
        if let TeePubKey::RSA { k_mod, .. } = &mut oversized {
            *k_mod = "a".repeat(4097);
        }
        assert_eq!(
            ExpectedLaunchQuote::new(&grant(AFFIRM, "a"), [1; 32], &oversized, [2; 48]).err(),
            Some(LaunchEvidenceError::InvalidRuntimeData)
        );
    }

    #[tokio::test]
    async fn software_only_binding_success_and_changed_report_or_init_failure() {
        let expected = expected(AFFIRM);
        let wire = software_wire(&expected);
        let verified = software_verify(expected.clone(), &wire, &software_verifier())
            .await
            .unwrap();
        assert_eq!(verified.evidence_sha384(), hash_hex(&wire));
        assert_eq!(
            verified.expected().canonical_runtime(),
            expected.canonical_runtime()
        );
        for field in ["report", "init"] {
            let mut changed: Value = serde_json::from_slice(&wire).unwrap();
            changed[field] = Value::String("00".repeat(48));
            let error = software_verify(
                expected.clone(),
                &serde_json::to_vec(&changed).unwrap(),
                &software_verifier(),
            )
            .await
            .err()
            .unwrap();
            assert_eq!(error, LaunchEvidenceError::VerificationFailed);
            assert!(!format!("{error:?} {error}").contains("confidential-software"));
        }
    }

    #[tokio::test]
    async fn software_only_empty_multiple_wrong_class_or_nonobject_claims_fail() {
        let expected = expected(AFFIRM);
        let wire = software_wire(&expected);
        for claims in [
            vec![],
            vec![(json!({}), "cpu".into())],
            vec![(json!([]), "cpu".into())],
            vec![(json!({"software_only": true}), "device".into())],
            vec![(json!({"software_only": true}), "cpu".into()); 2],
        ] {
            assert_eq!(
                software_verify(expected.clone(), &wire, &SoftwareOnlyVerifier { claims })
                    .await
                    .err(),
                Some(LaunchEvidenceError::InvalidClaims)
            );
        }
    }

    async fn engine(policy: &str) -> PolicyEngine<Regorus> {
        let engine = PolicyEngine::new(Arc::new(MemoryKeyValueStorage::default()));
        engine.set_policy("launch_cpu", policy, true).await.unwrap();
        engine
    }

    #[tokio::test]
    async fn software_only_appraisal_captures_actual_verified_input_and_strict_policy() {
        let expected = expected(AFFIRM);
        let wire = software_wire(&expected);
        let verified = software_verify(expected, &wire, &software_verifier())
            .await
            .unwrap();
        let appraisal = appraise_verified(
            verified,
            &engine(AFFIRM).await,
            "launch_cpu",
            Some(r#"{"reference":"fixture"}"#),
        )
        .await
        .unwrap();
        assert_eq!(appraisal.policy().decision(), PolicyDecision::Accepted);
        assert_eq!(
            appraisal.policy().capture().policy_bytes(),
            AFFIRM.as_bytes()
        );
        let input: Value =
            serde_json::from_slice(appraisal.policy().capture().input_bytes()).unwrap();
        assert_eq!(input["profile"], LAUNCH_QUOTE_PROFILE);
        assert_eq!(input["claims"], *appraisal.evidence().claims());
        assert_eq!(
            input["runtime_data"]["nonce"],
            appraisal.evidence().expected().nonce()
        );
    }

    #[tokio::test]
    async fn software_only_deny_unknown_nonbool_wrong_policy_and_invalid_reference_fail() {
        for (policy, expected_error) in [
            (
                "package policy\nlaunch_accepted := false\n",
                LaunchEvidenceError::PolicyDenied,
            ),
            (
                "package policy\nother := true\n",
                LaunchEvidenceError::PolicyDenied,
            ),
            (
                "package policy\nlaunch_accepted := \"true\"\n",
                LaunchEvidenceError::PolicyDenied,
            ),
        ] {
            let expected = expected(policy);
            let wire = software_wire(&expected);
            let verified = software_verify(expected, &wire, &software_verifier())
                .await
                .unwrap();
            assert_eq!(
                appraise_verified(verified, &engine(policy).await, "launch_cpu", None)
                    .await
                    .err(),
                Some(expected_error)
            );
        }
        let expected = expected(AFFIRM);
        let wire = software_wire(&expected);
        let verified = software_verify(expected.clone(), &wire, &software_verifier())
            .await
            .unwrap();
        assert_eq!(
            appraise_verified(
                verified,
                &engine("package policy\nlaunch_accepted := true\n").await,
                "launch_cpu",
                None
            )
            .await
            .err(),
            Some(LaunchEvidenceError::PolicyHashMismatch)
        );
        let verified = software_verify(expected, &wire, &software_verifier())
            .await
            .unwrap();
        assert_eq!(
            appraise_verified(
                verified,
                &engine(AFFIRM).await,
                "launch_cpu",
                Some("{secret-marker")
            )
            .await
            .err(),
            Some(LaunchEvidenceError::PolicyEvaluationFailed)
        );
    }
}
