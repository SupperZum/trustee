// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Opt-in capture of the policy, input and static data used by one evaluation.
//!
//! Captures policy provenance only. Callers authenticate input origins and
//! perform TEE verification, launch admission, and AS/KBS workflows separately.
//! Dynamic extensions, including RVPS callbacks, are disabled; evaluation uses
//! only the supplied static-data snapshot. Bounds apply to input bytes, not
//! evaluator CPU, output size, or wall time. Nondeterministic builtins may produce
//! different results on replay. Policy print output is discarded without entering
//! receipts or errors.

use super::rego::Regorus;
use crate::{EvaluationResult, PolicyEngine};
use sha2::{Digest, Sha384};
use std::{collections::HashSet, fmt};

pub const MAX_CAPTURE_OBJECT_BYTES: usize = 1024 * 1024;
pub const MAX_CAPTURE_TOTAL_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_CAPTURE_RULES: usize = 16;
pub const MAX_CAPTURE_POLICY_ID_BYTES: usize = 128;
pub const MAX_CAPTURE_RULE_BYTES: usize = 256;

/// SHA-384 of supplied bytes without JSON reserialization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteCommitment {
    sha384: String,
    byte_len: usize,
}

impl ByteCommitment {
    fn of(bytes: &[u8]) -> Self {
        Self {
            sha384: hex::encode(Sha384::digest(bytes)),
            byte_len: bytes.len(),
        }
    }

    pub fn sha384(&self) -> &str {
        &self.sha384
    }

    pub fn byte_len(&self) -> usize {
        self.byte_len
    }
}

/// An owned evaluation snapshot with no public constructor or raw Debug/serde.
/// Explicit accessors are the only way to inspect potentially sensitive bytes.
pub struct CapturedEvaluation {
    actual_policy_id: String,
    policy_bytes: Vec<u8>,
    input_bytes: Vec<u8>,
    data_bytes: Option<Vec<u8>>,
    result: EvaluationResult,
    policy_commitment: ByteCommitment,
    input_commitment: ByteCommitment,
    data_commitment: Option<ByteCommitment>,
}

impl CapturedEvaluation {
    pub fn actual_policy_id(&self) -> &str {
        &self.actual_policy_id
    }

    pub fn policy_bytes(&self) -> &[u8] {
        &self.policy_bytes
    }

    pub fn input_bytes(&self) -> &[u8] {
        &self.input_bytes
    }

    pub fn data_bytes(&self) -> Option<&[u8]> {
        self.data_bytes.as_deref()
    }

    pub fn result(&self) -> &EvaluationResult {
        &self.result
    }

    pub fn policy_commitment(&self) -> &ByteCommitment {
        &self.policy_commitment
    }

    pub fn input_commitment(&self) -> &ByteCommitment {
        &self.input_commitment
    }

    pub fn data_commitment(&self) -> Option<&ByteCommitment> {
        self.data_commitment.as_ref()
    }
}

/// Redacted errors retain no evaluator/storage error or source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureError {
    InvalidPolicyId,
    InvalidRules,
    BoundsExceeded,
    PolicyUnavailable,
    EvaluationFailed,
    InternalHashMismatch,
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidPolicyId => "capture policy identifier rejected",
            Self::InvalidRules => "capture rule selection rejected",
            Self::BoundsExceeded => "capture input bounds exceeded",
            Self::PolicyUnavailable => "capture policy unavailable",
            Self::EvaluationFailed => "captured policy evaluation failed",
            Self::InternalHashMismatch => "captured policy commitment mismatch",
        })
    }
}

impl std::error::Error for CaptureError {}

impl PolicyEngine<Regorus> {
    /// Fetch once and evaluate that exact policy with owned input/data snapshots.
    /// Unknown/false/nonboolean results are captured as facts, never accepted here.
    pub async fn evaluate_rego_captured(
        &self,
        data: Option<&str>,
        input: &str,
        actual_policy_id: &str,
        eval_rules: Vec<&str>,
    ) -> Result<CapturedEvaluation, CaptureError> {
        validate_selection(actual_policy_id, &eval_rules)?;
        validate_sizes(0, input.len(), data.map_or(0, str::len))?;
        // Own the bytes before the first await; do not re-read any input later.
        let input = input.to_owned();
        let data = data.map(str::to_owned);
        let policy = self
            .get_policy(actual_policy_id)
            .await
            .map_err(|_| CaptureError::PolicyUnavailable)?;
        validate_sizes(
            policy.len(),
            input.len(),
            data.as_ref().map_or(0, String::len),
        )?;
        let policy_commitment = ByteCommitment::of(policy.as_bytes());
        let input_commitment = ByteCommitment::of(input.as_bytes());
        let data_commitment = data
            .as_ref()
            .map(|bytes| ByteCommitment::of(bytes.as_bytes()));
        let result = self
            .engine
            .evaluate_captured(data.as_deref(), &input, &policy, eval_rules)
            .await
            .map_err(|_| CaptureError::EvaluationFailed)?;
        if result.policy_hash != policy_commitment.sha384 {
            return Err(CaptureError::InternalHashMismatch);
        }
        Ok(CapturedEvaluation {
            actual_policy_id: actual_policy_id.to_owned(),
            policy_bytes: policy.into_bytes(),
            input_bytes: input.into_bytes(),
            data_bytes: data.map(String::into_bytes),
            result,
            policy_commitment,
            input_commitment,
            data_commitment,
        })
    }
}

fn validate_sizes(policy: usize, input: usize, data: usize) -> Result<(), CaptureError> {
    if [policy, input, data]
        .iter()
        .any(|size| *size > MAX_CAPTURE_OBJECT_BYTES)
        || policy
            .checked_add(input)
            .and_then(|sum| sum.checked_add(data))
            .is_none_or(|sum| sum > MAX_CAPTURE_TOTAL_BYTES)
    {
        return Err(CaptureError::BoundsExceeded);
    }
    Ok(())
}

fn validate_selection(policy_id: &str, rules: &[&str]) -> Result<(), CaptureError> {
    if policy_id.is_empty()
        || policy_id.len() > MAX_CAPTURE_POLICY_ID_BYTES
        || !policy_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        return Err(CaptureError::InvalidPolicyId);
    }
    if rules.is_empty() || rules.len() > MAX_CAPTURE_RULES {
        return Err(CaptureError::InvalidRules);
    }
    let mut seen = HashSet::new();
    for rule in rules {
        if rule.len() > MAX_CAPTURE_RULE_BYTES
            || !rule.starts_with("data.")
            || !rule.split('.').all(|part| {
                let mut bytes = part.bytes();
                bytes
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
                    && bytes.all(|c| c.is_ascii_alphanumeric() || c == b'_')
            })
            || !seen.insert(*rule)
        {
            return Err(CaptureError::InvalidRules);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use key_value_storage::{
        memory::MemoryKeyValueStorage, KeyValueStorage, SetParameters, SetResult,
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    const ALLOW: &str = "package policy\nimport rego.v1\ndefault allow := false\nallow if { input.allow == true; data.permit == true }\n";
    const DENY: &str = "package policy\nimport rego.v1\nallow := false\n";
    const RULE: &str = "data.policy.allow";

    struct FlipOnFirstRead {
        inner: MemoryKeyValueStorage,
        reads: AtomicUsize,
        replacement: Option<Vec<u8>>,
    }

    #[async_trait]
    impl KeyValueStorage for FlipOnFirstRead {
        async fn set(
            &self,
            key: &str,
            value: &[u8],
            parameters: SetParameters,
        ) -> key_value_storage::Result<SetResult> {
            self.inner.set(key, value, parameters).await
        }
        async fn get(&self, key: &str) -> key_value_storage::Result<Option<Vec<u8>>> {
            let previous = self.inner.get(key).await?;
            if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
                if let Some(replacement) = &self.replacement {
                    self.inner
                        .set(key, replacement, SetParameters { overwrite: true })
                        .await?;
                }
            }
            Ok(previous)
        }
        async fn list(&self) -> key_value_storage::Result<Vec<String>> {
            self.inner.list().await
        }
        async fn delete(&self, key: &str) -> key_value_storage::Result<Option<Vec<u8>>> {
            self.inner.delete(key).await
        }
    }

    fn engine(replacement: Option<&str>) -> (PolicyEngine<Regorus>, Arc<FlipOnFirstRead>) {
        let storage = Arc::new(FlipOnFirstRead {
            inner: MemoryKeyValueStorage::default(),
            reads: AtomicUsize::new(0),
            replacement: replacement.map(|v| v.as_bytes().to_vec()),
        });
        (PolicyEngine::new(storage.clone()), storage)
    }

    #[tokio::test]
    async fn captures_exact_bytes_typed_commitments_and_legacy_evaluator_result() {
        let (engine, storage) = engine(None);
        engine.set_policy("launch_cpu", ALLOW, true).await.unwrap();
        let data = " {\"permit\":true} ";
        let input = "{\"allow\":true}";
        let captured = engine
            .evaluate_rego_captured(Some(data), input, "launch_cpu", vec![RULE])
            .await
            .unwrap();
        assert_eq!(storage.reads.load(Ordering::SeqCst), 1);
        assert_eq!(captured.actual_policy_id(), "launch_cpu");
        assert_eq!(captured.policy_bytes(), ALLOW.as_bytes());
        assert_eq!(captured.input_bytes(), input.as_bytes());
        assert_eq!(captured.data_bytes(), Some(data.as_bytes()));
        assert_eq!(captured.input_commitment().sha384(), "0b0b579ba61a016dab97984c0596a69aef9916354191492a00a8fa9900304c8f3901e2afbd86d5b435ddac1f78d24f89");
        assert_eq!(captured.data_commitment().unwrap().sha384(), "83bde452ccef5c3e795b53e4c25cb014cd7f5ab1f3679933cedb3684ab8eb23f625cdddc1956bff695c0fb5f8bcb464a");
        assert_eq!(captured.input_commitment().byte_len(), input.len());
        assert_eq!(captured.data_commitment().unwrap().byte_len(), data.len());
        assert_eq!(captured.policy_commitment().byte_len(), ALLOW.len());
        assert_eq!(
            captured.policy_commitment().sha384(),
            captured.result().policy_hash
        );
        assert_eq!(
            captured.result().eval_rules_result[RULE],
            Some(serde_json::Value::Bool(true))
        );
        let legacy = engine
            .evaluate_rego(Some(data), input, "launch_cpu", vec![RULE], vec![])
            .await
            .unwrap();
        assert_eq!(captured.result(), &legacy);
    }

    #[tokio::test]
    async fn storage_update_after_read_cannot_rewrite_the_captured_evaluation() {
        let (engine, storage) = engine(Some(DENY));
        engine.set_policy("launch_cpu", ALLOW, true).await.unwrap();
        let first = engine
            .evaluate_rego_captured(
                Some("{\"permit\":true}"),
                "{\"allow\":true}",
                "launch_cpu",
                vec![RULE],
            )
            .await
            .unwrap();
        assert_eq!(storage.reads.load(Ordering::SeqCst), 1);
        assert_eq!(first.policy_bytes(), ALLOW.as_bytes());
        assert_eq!(
            first.result().eval_rules_result[RULE],
            Some(serde_json::Value::Bool(true))
        );
        assert_eq!(
            storage.inner.get("launch_cpu.rego").await.unwrap().unwrap(),
            DENY.as_bytes()
        );
        let second = engine
            .evaluate_rego_captured(None, "{}", "launch_cpu", vec![RULE])
            .await
            .unwrap();
        assert_eq!(storage.reads.load(Ordering::SeqCst), 2);
        assert_eq!(second.policy_bytes(), DENY.as_bytes());
        assert_eq!(
            second.result().eval_rules_result[RULE],
            Some(serde_json::Value::Bool(false))
        );
        assert_ne!(first.policy_commitment(), second.policy_commitment());
        assert_eq!(first.policy_bytes(), ALLOW.as_bytes());
    }

    #[tokio::test]
    async fn static_data_snapshots_are_distinct_and_absence_is_not_an_empty_object() {
        let (engine, _) = engine(None);
        engine.set_policy("launch_cpu", ALLOW, true).await.unwrap();
        let allowed = engine
            .evaluate_rego_captured(
                Some("{\"permit\":true}"),
                "{\"allow\":true}",
                "launch_cpu",
                vec![RULE],
            )
            .await
            .unwrap();
        let denied = engine
            .evaluate_rego_captured(
                Some("{\"permit\":false}"),
                "{\"allow\":true}",
                "launch_cpu",
                vec![RULE],
            )
            .await
            .unwrap();
        assert_eq!(
            allowed.result().eval_rules_result[RULE],
            Some(serde_json::Value::Bool(true))
        );
        assert_eq!(
            denied.result().eval_rules_result[RULE],
            Some(serde_json::Value::Bool(false))
        );
        assert_ne!(allowed.data_commitment(), denied.data_commitment());
        let absent = engine
            .evaluate_rego_captured(None, "{}", "launch_cpu", vec![RULE])
            .await
            .unwrap();
        let empty = engine
            .evaluate_rego_captured(Some("{}"), "{}", "launch_cpu", vec![RULE])
            .await
            .unwrap();
        assert!(absent.data_bytes().is_none());
        assert!(absent.data_commitment().is_none());
        assert_eq!(empty.data_bytes(), Some(b"{}".as_slice()));
        assert_eq!(empty.data_commitment().unwrap().sha384(), "d2a23bc783e3aa38f401e13c7488505137c4954a7fd88331f1597c5ff71111dc807c7370a5b282c6da541c56ede69f30");
    }

    #[tokio::test]
    async fn deny_unknown_and_nonboolean_results_never_become_acceptance() {
        let (engine, _) = engine(None);
        engine.set_policy("launch_cpu", DENY, true).await.unwrap();
        let denied = engine
            .evaluate_rego_captured(None, "{}", "launch_cpu", vec![RULE, "data.policy.missing"])
            .await
            .unwrap();
        assert_eq!(
            denied.result().eval_rules_result[RULE],
            Some(serde_json::Value::Bool(false))
        );
        assert_ne!(
            denied.result().eval_rules_result["data.policy.missing"]
                .as_ref()
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        engine
            .set_policy(
                "launch_cpu",
                "package policy\nimport rego.v1\nallow := \"not-a-boolean\"\n",
                true,
            )
            .await
            .unwrap();
        let nonboolean = engine
            .evaluate_rego_captured(None, "{}", "launch_cpu", vec![RULE])
            .await
            .unwrap();
        assert!(nonboolean.result().eval_rules_result[RULE]
            .as_ref()
            .unwrap()
            .is_string());
    }

    #[tokio::test]
    async fn malformed_rule_selection_and_oversized_inputs_fail_before_storage_read() {
        let (engine, storage) = engine(None);
        for rules in [
            vec![],
            vec![RULE; MAX_CAPTURE_RULES + 1],
            vec![RULE, RULE],
            vec!["data..allow"],
            vec!["data.policy.allow; injection"],
        ] {
            assert_eq!(
                engine
                    .evaluate_rego_captured(None, "{}", "launch_cpu", rules)
                    .await
                    .err(),
                Some(CaptureError::InvalidRules)
            );
        }
        for id in [
            "",
            "../escape",
            "launch.rego",
            &"a".repeat(MAX_CAPTURE_POLICY_ID_BYTES + 1),
        ] {
            assert_eq!(
                engine
                    .evaluate_rego_captured(None, "{}", id, vec![RULE])
                    .await
                    .err(),
                Some(CaptureError::InvalidPolicyId)
            );
        }
        let oversized = "x".repeat(MAX_CAPTURE_OBJECT_BYTES + 1);
        assert_eq!(
            engine
                .evaluate_rego_captured(None, &oversized, "launch_cpu", vec![RULE])
                .await
                .err(),
            Some(CaptureError::BoundsExceeded)
        );
        assert_eq!(
            engine
                .evaluate_rego_captured(Some(&oversized), "{}", "launch_cpu", vec![RULE])
                .await
                .err(),
            Some(CaptureError::BoundsExceeded)
        );
        assert_eq!(storage.reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn policy_size_missing_policy_and_dynamic_rvps_errors_are_redacted() {
        let (engine, _) = engine(None);
        assert_eq!(
            engine
                .evaluate_rego_captured(None, "{}", "missing", vec![RULE])
                .await
                .err(),
            Some(CaptureError::PolicyUnavailable)
        );
        engine
            .set_policy("large", &"x".repeat(MAX_CAPTURE_OBJECT_BYTES + 1), true)
            .await
            .unwrap();
        assert_eq!(
            engine
                .evaluate_rego_captured(None, "{}", "large", vec![RULE])
                .await
                .err(),
            Some(CaptureError::BoundsExceeded)
        );
        let seed = "seed-private-payload";
        for (policy, input, data) in [
            (format!("package policy\nallow if {{ {seed}"), "{}".to_owned(), None),
            (DENY.to_owned(), format!("{{\"secret\":\"{seed}"), None),
            (DENY.to_owned(), "{}".to_owned(), Some(format!("{{\"secret\":\"{seed}"))),
            (format!("package policy\nimport rego.v1\nallow if {{ query_reference_value(\"{seed}\") == true }}"), "{}".to_owned(), None),
        ] {
            engine.set_policy("bad", &policy, true).await.unwrap();
            let error = engine.evaluate_rego_captured(data.as_deref(), &input, "bad", vec![RULE]).await.err().expect("unsafe evaluation must fail");
            assert_eq!(error, CaptureError::EvaluationFailed);
            assert!(!error.to_string().contains(seed));
            assert!(!format!("{error:?}").contains(seed));
            assert!(std::error::Error::source(&error).is_none());
        }
    }
}
