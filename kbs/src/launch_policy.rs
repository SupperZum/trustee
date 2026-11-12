// SPDX-License-Identifier: Apache-2.0

//! Opt-in facts from one KBS resource-policy evaluation.
//!
//! An allow result is not evidence of attestation acceptance, a fresh KBS session,
//! resource lookup, key release, JWE delivery, or an encrypted-image workflow.
//! The caller is responsible for authenticating claims and selecting the policy
//! and request data. This module neither creates those trust bindings nor changes
//! the legacy HTTP path. Captured input/data bytes require controlled disclosure.

use policy_engine::{
    capture::{CapturedEvaluation, MAX_CAPTURE_OBJECT_BYTES},
    policy::rego::Regorus,
    PolicyEngine,
};
use serde_json::Value;
use std::fmt;

/// The same rule requested by the KBS resource-policy HTTP path.
pub const RESOURCE_ALLOW_RULE: &str = "data.policy.allow";

/// A strict boolean allow and the owned snapshot used for that same evaluation.
/// No public constructor, deserialization, or raw Debug output is provided.
pub struct KbsPolicyFacts {
    capture: CapturedEvaluation,
}

impl KbsPolicyFacts {
    pub fn actual_policy_id(&self) -> &str {
        self.capture.actual_policy_id()
    }

    pub fn capture(&self) -> &CapturedEvaluation {
        &self.capture
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KbsPolicyError {
    InvalidData,
    ReservedPolicyData,
    EvaluationFailed,
    MissingDecision,
    NonBooleanDecision,
    Denied,
}

impl fmt::Display for KbsPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidData => "KBS static data must be a JSON object",
            Self::ReservedPolicyData => "KBS static data contains the reserved policy namespace",
            Self::EvaluationFailed => "KBS policy capture failed",
            Self::MissingDecision => "KBS policy allow decision missing",
            Self::NonBooleanDecision => "KBS policy allow decision is not boolean",
            Self::Denied => "KBS policy denied",
        })
    }
}

impl std::error::Error for KbsPolicyError {}

fn validate_static_data(data_json: &str) -> Result<(), KbsPolicyError> {
    // Preserve the capture API's pre-parse bound and its redacted failure class.
    if data_json.len() > MAX_CAPTURE_OBJECT_BYTES {
        return Err(KbsPolicyError::EvaluationFailed);
    }
    // Preserve Regorus JSON parsing and key semantics.
    let value =
        regorus::Value::from_json_str(data_json).map_err(|_| KbsPolicyError::InvalidData)?;
    let object = value.as_object().map_err(|_| KbsPolicyError::InvalidData)?;
    if object.contains_key(&regorus::Value::from("policy")) {
        return Err(KbsPolicyError::ReservedPolicyData);
    }
    Ok(())
}

/// Evaluates the selected policy once and returns facts only for strict `true`.
///
/// No dynamic extensions are installed. The decision comes only from the
/// evaluator result, never an extra caller acceptance flag. The capture retains
/// exact policy/input/data bytes from this evaluation, not a later policy lookup.
/// Static data must be an object without a top-level `policy` namespace, which
/// could otherwise shadow policy rules. Errors omit submitted data and policies.
pub async fn evaluate_kbs_policy(
    engine: &PolicyEngine<Regorus>,
    actual_policy_id: &str,
    data_json: &str,
    input_json: &str,
) -> Result<KbsPolicyFacts, KbsPolicyError> {
    validate_static_data(data_json)?;
    let capture = engine
        .evaluate_rego_captured(
            Some(data_json),
            input_json,
            actual_policy_id,
            vec![RESOURCE_ALLOW_RULE],
        )
        .await
        .map_err(|_| KbsPolicyError::EvaluationFailed)?;
    match capture.result().eval_rules_result.get(RESOURCE_ALLOW_RULE) {
        Some(Some(Value::Bool(true))) => {}
        Some(Some(Value::Bool(false))) => return Err(KbsPolicyError::Denied),
        Some(None) | None => return Err(KbsPolicyError::MissingDecision),
        Some(Some(_)) => return Err(KbsPolicyError::NonBooleanDecision),
    }
    Ok(KbsPolicyFacts { capture })
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_value_storage::memory::MemoryKeyValueStorage;
    use sha2::{Digest, Sha384};
    use std::sync::Arc;

    const DEFAULT_RESOURCE_POLICY: &str = include_str!("../sample_policies/default.rego");
    const RESOURCE_DATA: &str =
        "{\n  \"plugin\": \"resource\", \"resource-path\": [\"repo\",\"fixture\",\"key\"], \"query\": {}\n}";
    // The default resource policy checks sample evidence rather than EAR status.
    // These synthetic policy inputs have no authenticated attestation provenance.
    const NON_SAMPLE_INPUT: &str = r#"{
        "submods": {"cpu0": {
            "ear.status": "contraindicated",
            "ear.veraison.annotated-evidence": {"tdx": {}}
        }}
    }"#;
    const SAMPLE_INPUT: &str = r#"{
        "submods": {"cpu0": {
            "ear.veraison.annotated-evidence": {"sample": {}}
        }}
    }"#;

    async fn engine(policy: &str) -> PolicyEngine<Regorus> {
        let engine = PolicyEngine::new(Arc::new(MemoryKeyValueStorage::default()));
        engine
            .set_policy("resource-policy", policy, true)
            .await
            .unwrap();
        engine
    }

    fn sha384(bytes: &[u8]) -> String {
        hex::encode(Sha384::digest(bytes))
    }

    #[tokio::test]
    async fn default_resource_policy_capture_is_only_policy_evaluation() {
        let engine = engine(DEFAULT_RESOURCE_POLICY).await;
        let facts =
            evaluate_kbs_policy(&engine, "resource-policy", RESOURCE_DATA, NON_SAMPLE_INPUT)
                .await
                .unwrap();
        assert_eq!(facts.actual_policy_id(), "resource-policy");
        let capture = facts.capture();
        assert_eq!(capture.policy_bytes(), DEFAULT_RESOURCE_POLICY.as_bytes());
        assert_eq!(capture.input_bytes(), NON_SAMPLE_INPUT.as_bytes());
        assert_eq!(capture.data_bytes(), Some(RESOURCE_DATA.as_bytes()));
        assert_eq!(
            capture.policy_commitment().sha384(),
            sha384(DEFAULT_RESOURCE_POLICY.as_bytes())
        );
        assert_eq!(
            capture.input_commitment().sha384(),
            sha384(NON_SAMPLE_INPUT.as_bytes())
        );
        assert_eq!(
            capture.data_commitment().unwrap().sha384(),
            sha384(RESOURCE_DATA.as_bytes())
        );
        assert_eq!(
            capture.policy_commitment().byte_len(),
            DEFAULT_RESOURCE_POLICY.len()
        );
        assert_eq!(
            capture.input_commitment().byte_len(),
            NON_SAMPLE_INPUT.len()
        );
        assert_eq!(
            capture.data_commitment().unwrap().byte_len(),
            RESOURCE_DATA.len()
        );
        assert_eq!(
            capture.result().policy_hash,
            capture.policy_commitment().sha384()
        );

        // Facts retain the evaluated version after the policy store changes.
        engine
            .set_policy("resource-policy", "package policy\nallow := false", true)
            .await
            .unwrap();
        assert!(matches!(
            evaluate_kbs_policy(&engine, "resource-policy", RESOURCE_DATA, NON_SAMPLE_INPUT).await,
            Err(KbsPolicyError::Denied)
        ));
        assert_eq!(
            facts.capture().policy_bytes(),
            DEFAULT_RESOURCE_POLICY.as_bytes()
        );
    }

    #[tokio::test]
    async fn default_resource_policy_rejects_sample_and_other_plugin() {
        let engine = engine(DEFAULT_RESOURCE_POLICY).await;
        assert!(matches!(
            evaluate_kbs_policy(&engine, "resource-policy", RESOURCE_DATA, SAMPLE_INPUT).await,
            Err(KbsPolicyError::Denied)
        ));
        assert!(matches!(
            evaluate_kbs_policy(
                &engine,
                "resource-policy",
                r#"{"plugin":"other"}"#,
                NON_SAMPLE_INPUT
            )
            .await,
            Err(KbsPolicyError::Denied)
        ));
    }

    #[tokio::test]
    async fn missing_nonboolean_false_and_failed_evaluations_fail_closed() {
        for (policy, expected) in [
            ("package policy\nallow := false", KbsPolicyError::Denied),
            (
                "package policy\nother := true",
                KbsPolicyError::MissingDecision,
            ),
            (
                "package policy\nallow := \"true\"",
                KbsPolicyError::NonBooleanDecision,
            ),
            (
                "package policy\nallow := 1",
                KbsPolicyError::NonBooleanDecision,
            ),
            (
                "package policy\nallow := null",
                KbsPolicyError::NonBooleanDecision,
            ),
            ("this is not rego", KbsPolicyError::EvaluationFailed),
        ] {
            let engine = engine(policy).await;
            assert!(matches!(
                evaluate_kbs_policy(&engine, "resource-policy", "{}", "{}").await,
                Err(error) if error == expected
            ));
        }
        let engine = engine(DEFAULT_RESOURCE_POLICY).await;
        assert!(matches!(
            evaluate_kbs_policy(&engine, "resource-policy", "invalid JSON", "{}").await,
            Err(KbsPolicyError::InvalidData)
        ));
        assert!(matches!(
            evaluate_kbs_policy(&engine, "resource-policy", "{}", "invalid JSON").await,
            Err(KbsPolicyError::EvaluationFailed)
        ));
    }

    #[tokio::test]
    async fn static_data_cannot_supply_the_reserved_policy_namespace() {
        let engine = engine("package policy\nallow := false").await;
        for data in [
            r#"{"policy":{"allow":true}}"#,
            r#"{"policy":null}"#,
            r#"{"policy":{}}"#,
            r#"{"policy":{"nested":{"allow":true}}}"#,
            r#"{"\u0070olicy":{"allow":true}}"#,
            r#"{"policy":false,"policy":{"allow":true}}"#,
        ] {
            assert!(matches!(
                evaluate_kbs_policy(&engine, "resource-policy", data, "{}").await,
                Err(KbsPolicyError::ReservedPolicyData)
            ));
        }
        for data in ["null", "[]", "true", "1", r#""text""#, "malformed"] {
            assert!(matches!(
                evaluate_kbs_policy(&engine, "resource-policy", data, "{}").await,
                Err(KbsPolicyError::InvalidData)
            ));
        }
        assert!(matches!(
            evaluate_kbs_policy(
                &engine,
                "resource-policy",
                r#"{"references":{"policy":{"allow":true}}}"#,
                "{}"
            )
            .await,
            Err(KbsPolicyError::Denied)
        ));
        let oversized = " ".repeat(MAX_CAPTURE_OBJECT_BYTES + 1);
        assert!(matches!(
            evaluate_kbs_policy(&engine, "resource-policy", &oversized, "{}").await,
            Err(KbsPolicyError::EvaluationFailed)
        ));
    }
}
