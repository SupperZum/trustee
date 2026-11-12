//! Policy-only checks of Trustee source modules; no AS/KBS server is started.

#[cfg(feature = "capture")]
#[path = "../../../attestation-service/src/launch_policy.rs"]
mod as_launch_policy;

#[cfg(feature = "capture")]
#[path = "../../../kbs/src/launch_policy.rs"]
mod kbs_launch_policy;

use key_value_storage::memory::MemoryKeyValueStorage;
use policy_engine::{rego::Regorus, PolicyEngine};
use std::sync::Arc;

#[tokio::test]
async fn legacy_evaluation_keeps_the_same_result_with_capture_off_or_on() {
    let engine = PolicyEngine::<Regorus>::new(Arc::new(MemoryKeyValueStorage::default()));
    engine
        .set_policy("baseline", "package policy\nallow := true\n", true)
        .await
        .unwrap();
    let result = engine
        .evaluate_rego(None, "{}", "baseline", vec!["data.policy.allow"], vec![])
        .await
        .unwrap();
    assert_eq!(
        result.eval_rules_result["data.policy.allow"],
        Some(serde_json::Value::Bool(true))
    );
    assert_eq!(result.policy_hash.len(), 96);
}

#[tokio::test]
async fn legacy_print_behavior_is_preserved() {
    let engine = PolicyEngine::<Regorus>::new(Arc::new(MemoryKeyValueStorage::default()));
    engine
        .set_policy(
            "legacy_print",
            "package policy\nimport rego.v1\nallow if { print(input.label); true }\n",
            true,
        )
        .await
        .unwrap();
    // Public synthetic marker for checking legacy evaluator print behavior.
    let result = engine
        .evaluate_rego(
            None,
            r#"{"label":"onb17-legacy-print-marker"}"#,
            "legacy_print",
            vec!["data.policy.allow"],
            vec![],
        )
        .await
        .unwrap();
    assert_eq!(
        result.eval_rules_result["data.policy.allow"],
        Some(serde_json::json!(true))
    );
}

#[cfg(feature = "capture")]
#[tokio::test]
async fn as_facts_capture_actual_suffixed_policy_and_supplied_inputs() {
    use as_launch_policy::{evaluate_launch_policy, PolicyDecision, ReferenceDataMode};
    let engine = PolicyEngine::<Regorus>::new(Arc::new(MemoryKeyValueStorage::default()));
    let policy = "package policy\nimport rego.v1\ndefault launch_accepted := false\nlaunch_accepted if { input.platform == \"fixture\"; data.allowed == true }\ntrust_claims := {\"instance_identity\": 2}\nextensions := []\n";
    engine.set_policy("launch_cpu", policy, true).await.unwrap();
    let claims = r#"{"platform":"fixture","caller_accepted":false}"#;
    let references = r#"{ "allowed" : true }"#;
    let facts = evaluate_launch_policy(&engine, "launch_cpu", claims, Some(references))
        .await
        .unwrap();
    assert_eq!(facts.decision(), PolicyDecision::Accepted);
    assert_eq!(
        facts.reference_data_mode(),
        ReferenceDataMode::ImmutableDataOnly
    );
    assert_eq!(facts.capture().actual_policy_id(), "launch_cpu");
    assert_eq!(facts.capture().policy_bytes(), policy.as_bytes());
    assert_eq!(facts.capture().input_bytes(), claims.as_bytes());
    assert_eq!(facts.capture().data_bytes(), Some(references.as_bytes()));

    let changed = "package policy\nimport rego.v1\nlaunch_accepted := false\n";
    engine
        .set_policy("launch_cpu", changed, true)
        .await
        .unwrap();
    let next = evaluate_launch_policy(&engine, "launch_cpu", claims, Some(references))
        .await
        .unwrap();
    assert_eq!(next.decision(), PolicyDecision::Denied);
    assert_ne!(
        facts.capture().policy_commitment(),
        next.capture().policy_commitment()
    );
    assert_eq!(facts.capture().policy_bytes(), policy.as_bytes());
}

#[cfg(feature = "capture")]
#[tokio::test]
async fn as_policy_result_is_not_an_input_acceptance_flag_or_token() {
    use as_launch_policy::{evaluate_launch_policy, PolicyDecision};
    let engine = PolicyEngine::<Regorus>::new(Arc::new(MemoryKeyValueStorage::default()));
    let forged_claim = r#"{"launch_accepted":true,"accepted":true}"#;
    for (body, expected) in [
        ("launch_accepted := false", PolicyDecision::Denied),
        ("launch_accepted := true", PolicyDecision::Accepted),
        ("unrelated := true", PolicyDecision::Unknown),
        ("launch_accepted := null", PolicyDecision::Unknown),
        ("launch_accepted := \"true\"", PolicyDecision::Unknown),
        ("launch_accepted := 1", PolicyDecision::Unknown),
    ] {
        engine
            .set_policy(
                "decision_cpu",
                &format!("package policy\nimport rego.v1\n{body}\n"),
                true,
            )
            .await
            .unwrap();
        let facts = evaluate_launch_policy(&engine, "decision_cpu", forged_claim, None)
            .await
            .unwrap();
        assert_eq!(facts.decision(), expected);
    }
}

#[cfg(feature = "capture")]
#[tokio::test]
async fn as_policy_dynamic_references_fail_with_redacted_errors() {
    let engine = PolicyEngine::<Regorus>::new(Arc::new(MemoryKeyValueStorage::default()));
    engine.set_policy("rvps_cpu", "package policy\nimport rego.v1\nlaunch_accepted := query_reference_value(\"private-fixture-reference\")\n", true).await.unwrap();
    let result = as_launch_policy::evaluate_launch_policy(&engine, "rvps_cpu", "{}", None).await;
    let error = match result {
        Ok(_) => panic!("dynamic references require an explicit captured resolver"),
        Err(error) => error,
    };
    assert!(!error.to_string().contains("private-fixture-reference"));
    assert!(!format!("{error:?}").contains("private-fixture-reference"));
}

#[cfg(feature = "capture")]
#[tokio::test]
async fn static_data_cannot_override_as_policy_decision() {
    use as_launch_policy::{evaluate_launch_policy, PolicyDecision};
    let engine = PolicyEngine::<Regorus>::new(Arc::new(MemoryKeyValueStorage::default()));
    engine
        .set_policy(
            "deny_cpu",
            "package policy\nimport rego.v1\nlaunch_accepted := false\nallow := false\n",
            true,
        )
        .await
        .unwrap();
    let overlay = r#"{"policy":{"launch_accepted":true,"allow":true}}"#;
    if let Ok(facts) = evaluate_launch_policy(&engine, "deny_cpu", "{}", Some(overlay)).await {
        assert_ne!(facts.decision(), PolicyDecision::Accepted);
    }
}

#[cfg(feature = "capture")]
#[tokio::test]
async fn static_data_cannot_override_kbs_policy_decision() {
    let engine = PolicyEngine::<Regorus>::new(Arc::new(MemoryKeyValueStorage::default()));
    engine
        .set_policy("deny", "package policy\nallow := false\n", true)
        .await
        .unwrap();
    assert!(kbs_launch_policy::evaluate_kbs_policy(
        &engine,
        "deny",
        r#"{"policy":{"allow":true}}"#,
        "{}",
    )
    .await
    .is_err());
}

#[cfg(feature = "capture")]
#[tokio::test]
async fn static_data_shape_and_reserved_policy_namespace_fail_closed() {
    let engine = PolicyEngine::<Regorus>::new(Arc::new(MemoryKeyValueStorage::default()));
    engine
        .set_policy(
            "shape",
            "package policy\nlaunch_accepted := true\nallow := true\n",
            true,
        )
        .await
        .unwrap();
    for data in [
        "null",
        "[]",
        "true",
        "{",
        r#"{"policy":null}"#,
        r#"{"policy":{}}"#,
        r#"{"policy":{"trust_claims":{"instance_identity":2}}}"#,
        r#"{"\u0070olicy":{"extensions":["forged"]}}"#,
        r#"{"policy":true,"policy":{}}"#,
    ] {
        assert!(
            as_launch_policy::evaluate_launch_policy(&engine, "shape", "{}", Some(data))
                .await
                .is_err()
        );
        assert!(
            kbs_launch_policy::evaluate_kbs_policy(&engine, "shape", data, "{}")
                .await
                .is_err()
        );
    }
    let oversized = format!(
        "{{\"padding\":\"{}\"}}",
        "x".repeat(policy_engine::capture::MAX_CAPTURE_OBJECT_BYTES)
    );
    assert!(
        as_launch_policy::evaluate_launch_policy(&engine, "shape", "{}", Some(&oversized))
            .await
            .is_err()
    );
    assert!(
        kbs_launch_policy::evaluate_kbs_policy(&engine, "shape", &oversized, "{}")
            .await
            .is_err()
    );
}

#[cfg(feature = "capture")]
#[tokio::test]
async fn capture_does_not_print_input_or_reference_data() {
    let engine = PolicyEngine::<Regorus>::new(Arc::new(MemoryKeyValueStorage::default()));
    engine
        .set_policy(
            "printing",
            "package policy\nimport rego.v1\nallow if { print(input.secret, data.secret); true }\n",
            true,
        )
        .await
        .unwrap();
    // Public synthetic markers for checking capture-print suppression in
    // process output; neither marker contains a real secret.
    let capture = engine
        .evaluate_rego_captured(
            Some(r#"{"secret":"onb17-print-reference-marker"}"#),
            r#"{"secret":"onb17-print-input-marker"}"#,
            "printing",
            vec!["data.policy.allow"],
        )
        .await
        .unwrap();
    assert_eq!(
        capture.result().eval_rules_result["data.policy.allow"],
        Some(serde_json::json!(true))
    );
}
