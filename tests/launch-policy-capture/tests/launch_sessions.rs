//! AS/KBS source tests using the verifier trait and factory without a TDX
//! backend. Positive quote fixtures use software verifiers.
#![cfg(all(feature = "launch-session", not(feature = "launch-http")))]

extern crate self as attestation_service;

// Match the production AS config module's VerifierConfig re-export.
pub mod config {
    pub use verifier::VerifierConfig;
}

#[path = "../../../attestation-service/src/launch_evidence.rs"]
pub mod launch_evidence;
#[path = "../../../attestation-service/src/launch_policy.rs"]
pub mod launch_policy;
#[path = "../../../kbs/src/launch_session.rs"]
pub mod launch_session;
