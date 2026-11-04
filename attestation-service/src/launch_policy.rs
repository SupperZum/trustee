// SPDX-License-Identifier: Apache-2.0

//! Capture one launch-policy evaluation.
//!
//! The caller supplies claims from AS verification and selects the policy and
//! reference context from trusted configuration. This helper does not verify
//! grants, TEE evidence, recorder/key origin, or execution. Caller-supplied JSON
//! has no verified provenance.
//!
//! A decision covers only its input/data bytes and confers no launch admission,
//! AS/KBS credential, signed appraisal, or runtime capability. Reference data
//! are immutable for this evaluation; RVPS authenticity is not checked and
//! dynamic RVPS callbacks are unsupported.

use policy_engine::{
    capture::{CaptureError, CapturedEvaluation, MAX_CAPTURE_OBJECT_BYTES},
    rego::Regorus,
    PolicyEngine,
};
use std::fmt;

/// A fixed policy rule; caller-provided metadata cannot substitute its result.
pub const LAUNCH_ACCEPTED_RULE: &str = "data.policy.launch_accepted";
pub const TRUST_CLAIMS_RULE: &str = "data.policy.trust_claims";
pub const EXTENSIONS_RULE: &str = "data.policy.extensions";

/// The outcome of the selected policy on the supplied JSON, not authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyDecision {
    /// Only a literal policy-result boolean `true` has this meaning.
    Accepted,
    Denied,
    /// Missing, undefined, null, and non-boolean results never imply acceptance.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceDataMode {
    /// Data bytes are captured with this evaluation; no live RVPS calls occur.
    ImmutableDataOnly,
}

/// Redacted validation/evaluation failures; submitted JSON is never included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AsPolicyError {
    InvalidData,
    ReservedPolicyData,
    Capture(CaptureError),
}

impl fmt::Display for AsPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidData => "AS static data must be a JSON object",
            Self::ReservedPolicyData => "AS static data contains the reserved policy namespace",
            Self::Capture(_) => "AS policy capture failed",
        })
    }
}

impl std::error::Error for AsPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Capture(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CaptureError> for AsPolicyError {
    fn from(error: CaptureError) -> Self {
        Self::Capture(error)
    }
}

fn validate_static_data(data_json: &str) -> Result<(), AsPolicyError> {
    // Keep the capture API's bound before parsing potentially hostile JSON.
    if data_json.len() > MAX_CAPTURE_OBJECT_BYTES {
        return Err(AsPolicyError::Capture(CaptureError::BoundsExceeded));
    }
    // Use exactly the evaluator's parser, including its JSON number/key semantics.
    let value = regorus::Value::from_json_str(data_json).map_err(|_| AsPolicyError::InvalidData)?;
    let object = value.as_object().map_err(|_| AsPolicyError::InvalidData)?;
    if object.contains_key(&regorus::Value::from("policy")) {
        return Err(AsPolicyError::ReservedPolicyData);
    }
    Ok(())
}

/// Owned same-evaluation facts. No Deserialize, Debug, or public constructor.
/// Policy, input, data, and result payloads may be confidential; inspect/export
/// them explicitly through `capture` only under the caller's disclosure policy.
pub struct AsPolicyFacts {
    capture: CapturedEvaluation,
    decision: PolicyDecision,
}

impl AsPolicyFacts {
    pub fn capture(&self) -> &CapturedEvaluation {
        &self.capture
    }

    pub fn decision(&self) -> PolicyDecision {
        self.decision
    }

    pub fn reference_data_mode(&self) -> ReferenceDataMode {
        ReferenceDataMode::ImmutableDataOnly
    }
}

/// Evaluate the policy once and retain its exact input snapshots.
///
/// `selected_policy_id` is the caller's already selected full policy identifier,
/// including its TEE-class suffix where applicable. This helper neither chooses
/// a trusted policy nor appends a guessed suffix. `claims_json` must come from
/// AS verification before these facts can participate in an appraisal.
/// The fixed decision rule is evaluated alongside trust claims and extensions;
/// it is never read directly from an input field or caller-supplied boolean.
/// Static data must be an object without the reserved top-level `policy` key,
/// preventing data from shadowing the selected policy's rules.
pub async fn evaluate_launch_policy(
    engine: &PolicyEngine<Regorus>,
    selected_policy_id: &str,
    claims_json: &str,
    immutable_reference_data_json: Option<&str>,
) -> Result<AsPolicyFacts, AsPolicyError> {
    if let Some(data_json) = immutable_reference_data_json {
        validate_static_data(data_json)?;
    }
    let capture = engine
        .evaluate_rego_captured(
            immutable_reference_data_json,
            claims_json,
            selected_policy_id,
            vec![LAUNCH_ACCEPTED_RULE, TRUST_CLAIMS_RULE, EXTENSIONS_RULE],
        )
        .await?;

    let decision = match capture
        .result()
        .eval_rules_result
        .get(LAUNCH_ACCEPTED_RULE)
        .and_then(Option::as_ref)
        .and_then(|value| value.as_bool())
    {
        Some(true) => PolicyDecision::Accepted,
        Some(false) => PolicyDecision::Denied,
        None => PolicyDecision::Unknown,
    };
    Ok(AsPolicyFacts { capture, decision })
}
