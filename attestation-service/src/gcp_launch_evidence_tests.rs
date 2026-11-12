use super::*;
use async_trait::async_trait;
use execution_proof_contract::{
    verify_launch_grant, GrantExpectations, LaunchBinding, LaunchGrant, Signed, ValidityWindow,
    GRANT_PURPOSE, VERSION,
};
use execution_proof_verifier::{
    gcp_boot_evidence::{GcpInstanceIdentity, QuotePaddingPolicy},
    gcp_tdx_policy::{
        GCP_TDX_ALLOWED_ATTRIBUTES, GCP_TDX_POLICY_PURPOSE, GCP_TDX_POLICY_VERSION,
        INTEL_TDX_MODULE_1_5_34_MR_SEAM,
    },
};
use key_value_storage::memory::MemoryKeyValueStorage;
use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};

const QUOTE: &[u8] = include_bytes!(
    "../../../execution-proof-prototype/verifier/tests/fixtures/gcp_boot_v1/baseline-quote.bin"
);
const LOG: &[u8] = include_bytes!(
    "../../../execution-proof-prototype/verifier/tests/fixtures/gcp_boot_v1/baseline-ccel.bin"
);
const TABLE: &[u8] = include_bytes!(
    "../../../execution-proof-prototype/verifier/tests/fixtures/gcp_boot_v1/baseline-acpi-ccel.bin"
);
const AFFIRM:&str="package policy\nimport rego.v1\nlaunch_accepted if { input.profile == \"onb17.gcp-launch-quote.v2\"; input.boot_binding_sha384 != \"\"; input.runtime_data.nonce != \"\"; data.reference == \"fixture\" }\ntrust_claims := {}\nextensions := []\n";
fn binding() -> GcpBootBindingV1 {
    GcpBootBindingV1::new([1; 48], [2; 48], [3; 48], [4; 48]).unwrap()
}
fn grant(policy: &str, binding: &GcpBootBindingV1, attempt: &str) -> VerifiedLaunchGrant {
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
            profile_sha384: binding.digest_sha384().unwrap(),
            launch_policy_sha384: hash(policy.as_bytes()),
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
    verify_launch_grant(
        &serde_json::to_vec(&Signed {
            statement: grant,
            signature,
        })
        .unwrap(),
        &expected,
        10,
    )
    .unwrap()
}
fn key() -> TeePubKey {
    TeePubKey::RSA {
        alg: "RSA-OAEP-256".into(),
        k_mod: "AQID".into(),
        k_exp: "AQAB".into(),
    }
}
fn boot_policy() -> GcpBootEvidencePolicy {
    GcpBootEvidencePolicy{expected_pe_sha384:"c4240c5a835ca1c7b6b9c3dd762477870ba5b7a295ec0f551eb45d442be8926b3d887ea59fa348ff5e8832aaf595c8b4".into(),expected_firmware_mrtd:"f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3".into(),expected_instance:GcpInstanceIdentity{instance_id:1159420029374854386,numerical_project_id:876967775446,zone:"us-central1-a".into()},quote_padding:QuotePaddingPolicy::GcpTsmZeroPadded8000}
}
fn module_policy() -> GcpTdxModulePolicyV1 {
    GcpTdxModulePolicyV1 {
        version: GCP_TDX_POLICY_VERSION,
        purpose: GCP_TDX_POLICY_PURPOSE.into(),
        expected_mr_seam: INTEL_TDX_MODULE_1_5_34_MR_SEAM.into(),
        allowed_td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
    }
}
fn expected(policy: &str) -> ExpectedGcpLaunchQuote {
    ExpectedGcpLaunchQuote::new(
        &grant(policy, &binding(), "attempt"),
        binding(),
        [7; 32],
        &key(),
        boot_policy(),
        module_policy(),
    )
    .unwrap()
}

// A mutated retained quote is structurally useful but cryptographically INVALID.
// Only this private test seam bypasses QVL; no public result uses this fixture.
pub(super) fn wire(expected: &ExpectedGcpLaunchQuote) -> Vec<u8> {
    let mut q = QUOTE.to_vec();
    q[568..632].copy_from_slice(expected.report_data());
    GcpLaunchEvidence::new(q, TABLE.to_vec(), LOG.to_vec())
        .unwrap()
        .encode()
        .unwrap()
}
fn claims(boot: &StructuralBootEvidence) -> Value {
    let q = &boot.quote;
    json!({"quote":{"body":{"report_data":hex::encode(q.report_data),"mr_config_id":hex::encode(q.mr_config_id),"mr_td":hex::encode(q.mr_td),"mr_owner":hex::encode(q.mr_owner),"mr_seam":hex::encode(q.mr_seam),"td_attributes":hex::encode(q.td_attributes.to_le_bytes()),"rtmr_0":hex::encode(q.rtmrs[0]),"rtmr_1":hex::encode(q.rtmrs[1]),"rtmr_2":hex::encode(q.rtmrs[2]),"rtmr_3":hex::encode(q.rtmrs[3])}},"report_data":hex::encode(q.report_data),"init_data":hex::encode(q.mr_config_id),"td_attributes":{"debug":false},"tcb_status":"UpToDate","collateral_expiration_status":"0"})
}
struct SoftwareVerifier {
    report: [u8; 64],
    claims: Vec<(Value, String)>,
    fail: bool,
}
#[async_trait]
impl Verifier for SoftwareVerifier {
    async fn evaluate(
        &self,
        evidence: Value,
        report: &ReportData,
        init: &InitDataHash,
    ) -> anyhow::Result<Vec<(Value, String)>> {
        let (ReportData::Value(value), InitDataHash::NotProvided) = (report, init) else {
            anyhow::bail!("software fixture binding mode");
        };
        let raw = STANDARD.decode(evidence["quote"].as_str().unwrap())?;
        if *value != self.report || raw[568..632] != self.report || self.fail {
            anyhow::bail!("secret-marker");
        }
        Ok(self.claims.clone())
    }
}
pub(super) async fn software_verify(
    expected: ExpectedGcpLaunchQuote,
    raw: &[u8],
    mutate: fn(&mut Vec<(Value, String)>),
    fail: bool,
) -> Result<GcpVerifiedLaunchEvidence, GcpLaunchEvidenceError> {
    let (evidence, boot, digest) = checked_evidence(&expected, raw)?;
    let mut values = vec![(claims(&boot), "cpu".into())];
    mutate(&mut values);
    let verifier = SoftwareVerifier {
        report: *expected.report_data(),
        claims: values,
        fail,
    };
    verify_with(expected, evidence, boot, digest, &verifier).await
}
async fn engine(policy: &str) -> PolicyEngine<Regorus> {
    let e = PolicyEngine::new(Arc::new(MemoryKeyValueStorage::default()));
    e.set_policy("launch_cpu", policy, true).await.unwrap();
    e
}

#[test]
fn expected_context_requires_grant_profile_and_binds_nonce_key_and_full64() {
    let b = binding();
    let g = grant(AFFIRM, &b, "attempt");
    let a = ExpectedGcpLaunchQuote::new(
        &g,
        b.clone(),
        [7; 32],
        &key(),
        boot_policy(),
        module_policy(),
    )
    .unwrap();
    assert_eq!(
        &a.report_data()[..48],
        Sha384::digest(a.canonical_runtime()).as_slice()
    );
    assert_eq!(&a.report_data()[48..], &[0; 16]);
    assert!(a.nonce().starts_with("onb17-gcp-launch-v2:"));
    let runtime: Value = serde_json::from_slice(a.canonical_runtime()).unwrap();
    assert_eq!(runtime["additional-evidence"], "");
    assert_eq!(runtime["tee-pubkey"], serde_json::to_value(key()).unwrap());
    let other = ExpectedGcpLaunchQuote::new(
        &g,
        b.clone(),
        [8; 32],
        &key(),
        boot_policy(),
        module_policy(),
    )
    .unwrap();
    assert_ne!(a.nonce(), other.nonce());
    let mut k = key();
    if let TeePubKey::RSA { k_mod, .. } = &mut k {
        *k_mod = "BAUG".into();
    }
    let other =
        ExpectedGcpLaunchQuote::new(&g, b.clone(), [7; 32], &k, boot_policy(), module_policy())
            .unwrap();
    assert_ne!(a.report_data(), other.report_data());
    let other = ExpectedGcpLaunchQuote::new(
        &grant(AFFIRM, &b, "other"),
        b.clone(),
        [7; 32],
        &key(),
        boot_policy(),
        module_policy(),
    )
    .unwrap();
    assert_ne!(a.nonce(), other.nonce());
    let mut changed = b.clone();
    changed.config_sha384 = "ab".repeat(48);
    let changed_expected = ExpectedGcpLaunchQuote::new(
        &grant(AFFIRM, &changed, "attempt"),
        changed.clone(),
        [7; 32],
        &key(),
        boot_policy(),
        module_policy(),
    )
    .unwrap();
    assert_ne!(a.nonce(), changed_expected.nonce());
    assert!(ExpectedGcpLaunchQuote::new(
        &g,
        changed,
        [7; 32],
        &key(),
        boot_policy(),
        module_policy()
    )
    .is_err());
    assert!(
        ExpectedGcpLaunchQuote::new(&g, b, [0; 32], &key(), boot_policy(), module_policy())
            .is_err()
    );
}

#[test]
fn strict_codec_legacy_profile_and_actual_report_boot_predicates_fail_closed() {
    let e = expected(AFFIRM);
    let raw = wire(&e);
    assert!(checked_evidence(&e, &raw).is_ok());
    for byte in 0..64 {
        let mut v = GcpLaunchEvidence::decode(&raw).unwrap();
        v.tdx_quote[568 + byte] ^= 1;
        assert!(checked_evidence(&e, &v.encode().unwrap()).is_err());
    }
    let mut v: Value = serde_json::from_slice(&raw).unwrap();
    v["version"] = 1.into();
    assert!(checked_evidence(&e, &serde_json::to_vec(&v).unwrap()).is_err());
    let legacy = json!({"quote":STANDARD.encode(QUOTE),"cc_eventlog":null});
    assert!(checked_evidence(&e, &serde_json::to_vec(&legacy).unwrap()).is_err());
    let mut wrong = e.clone();
    wrong.boot_policy.expected_pe_sha384 = "ab".repeat(48);
    assert!(checked_evidence(&wrong, &raw).is_err());
    let mut wrong = e.clone();
    wrong.boot_policy.expected_instance.instance_id += 1;
    assert!(checked_evidence(&wrong, &raw).is_err());
    let mut wrong = e;
    wrong.module_policy.allowed_td_attributes = 0;
    assert!(checked_evidence(&wrong, &raw).is_err());
}

#[tokio::test]
async fn private_software_seam_requires_exact_normalized_crypto_facts() {
    let e = expected(AFFIRM);
    let raw = wire(&e);
    let result = software_verify(e.clone(), &raw, |_| {}, false)
        .await
        .unwrap();
    assert_eq!(result.evidence_sha384(), hash(&raw));
    type ClaimsMutation = fn(&mut Vec<(Value, String)>);
    let changes: &[ClaimsMutation] = &[
        |v| v.clear(),
        |v| v[0].1 = "device".into(),
        |v| v.push(v[0].clone()),
        |v| v[0].0["report_data"] = "ab".repeat(64).into(),
        |v| v[0].0["quote"]["body"]["mr_td"] = "ab".repeat(48).into(),
        |v| v[0].0["init_data"] = "ab".repeat(48).into(),
        |v| v[0].0["tcb_status"] = "OutOfDate".into(),
        |v| v[0].0["collateral_expiration_status"] = "1".into(),
        |v| v[0].0["td_attributes"]["debug"] = true.into(),
    ];
    for change in changes {
        assert_eq!(
            software_verify(e.clone(), &raw, *change, false).await.err(),
            Some(GcpLaunchEvidenceError::InvalidClaims)
        );
    }
    let error = software_verify(e, &raw, |_| {}, true).await.err().unwrap();
    assert_eq!(error, GcpLaunchEvidenceError::VerificationFailed);
    assert!(!error.to_string().contains("secret-marker"));
}

#[tokio::test]
async fn captured_policy_contains_actual_bound_b_runtime_and_claims() {
    let e = expected(AFFIRM);
    let raw = wire(&e);
    let evidence = software_verify(e, &raw, |_| {}, false).await.unwrap();
    let app = appraise_verified(
        evidence,
        &engine(AFFIRM).await,
        "launch_cpu",
        Some(r#"{"reference":"fixture"}"#),
    )
    .await
    .unwrap();
    assert_eq!(app.policy().decision(), PolicyDecision::Accepted);
    assert_eq!(app.policy().capture().policy_bytes(), AFFIRM.as_bytes());
    let input: Value = serde_json::from_slice(app.policy().capture().input_bytes()).unwrap();
    assert_eq!(
        input["boot_binding"],
        serde_json::to_value(binding()).unwrap()
    );
    assert_eq!(
        input["boot_binding_sha384"],
        binding().digest_sha384().unwrap()
    );
    assert_eq!(input["claims"], *app.evidence().claims());
    assert_eq!(
        input["runtime_data"]["nonce"],
        app.evidence().expected().nonce()
    );
    assert!(input.get("init_data_sha384").is_none());
}

#[tokio::test]
async fn denied_unknown_wrong_policy_and_bad_reference_never_appraise() {
    for policy in [
        "package policy\nlaunch_accepted := false\n",
        "package policy\nother := true\n",
        "package policy\nlaunch_accepted := \"true\"\n",
    ] {
        let e = expected(policy);
        let raw = wire(&e);
        let evidence = software_verify(e, &raw, |_| {}, false).await.unwrap();
        assert_eq!(
            appraise_verified(evidence, &engine(policy).await, "launch_cpu", None)
                .await
                .err(),
            Some(GcpLaunchEvidenceError::PolicyDenied)
        );
    }
    let e = expected(AFFIRM);
    let raw = wire(&e);
    let evidence = software_verify(e.clone(), &raw, |_| {}, false)
        .await
        .unwrap();
    assert_eq!(
        appraise_verified(
            evidence,
            &engine("package policy\nlaunch_accepted := true\n").await,
            "launch_cpu",
            None
        )
        .await
        .err(),
        Some(GcpLaunchEvidenceError::PolicyHashMismatch)
    );
    let evidence = software_verify(e, &raw, |_| {}, false).await.unwrap();
    assert_eq!(
        appraise_verified(
            evidence,
            &engine(AFFIRM).await,
            "launch_cpu",
            Some("{secret-marker")
        )
        .await
        .err(),
        Some(GcpLaunchEvidenceError::PolicyEvaluationFailed)
    );
}
