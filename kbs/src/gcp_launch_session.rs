// SPDX-License-Identifier: Apache-2.0

//! Attempt-scoped, ephemeral sessions for the opt-in launch quote path.
//!
//! A captured appraisal is an immutable verification/policy transcript, not a
//! token, resource permission, key release, or execution proof. This module never
//! reads legacy KBS sessions. Atomic transitions apply only to clones of this
//! instance in one process; restart discards every session. Durable admission,
//! cross-process coordination, and protected recorder origin are unsupported here.

use attestation_service::{
    config::VerifierConfig,
    gcp_launch_evidence::{appraise_gcp_launch_quote, AppraisedGcpLaunch, ExpectedGcpLaunchQuote},
};
#[cfg(feature = "launch-gcp-credentials")]
use execution_proof_contract::LaunchBinding;
use execution_proof_contract::{
    gcp_session::{verify_operation_pop, verify_recorder_session_pop, SessionOperation},
    verify_launch_grant, GrantExpectations, VerifiedLaunchGrant, MAX_WIRE_BYTES,
};
use kbs_types::TeePubKey;
use key_value_storage::StorageProvider;
use policy_engine::{capture::MAX_CAPTURE_OBJECT_BYTES, rego::Regorus, PolicyEngine};
use ring::{digest, rand::SecureRandom};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

pub const MAX_SESSION_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SESSIONS: usize = 1024;

/// Trusted configuration, selected by the embedding server, never by a request.
/// No raw Debug/serde is provided for policy or reference data.
pub struct SessionConfig {
    pub grant_expectations: GrantExpectations,
    pub boot_binding: execution_proof_contract::gcp_boot_binding::GcpBootBindingV1,
    pub boot_policy: execution_proof_verifier::gcp_boot_evidence::GcpBootEvidencePolicy,
    pub module_policy: execution_proof_verifier::gcp_tdx_policy::GcpTdxModulePolicyV1,
    pub selected_policy_id: String,
    pub reference_data: Option<String>,
    pub capacity: usize,
}

/// The clock is fixed at construction; requests cannot supply their own time.
pub trait SessionClock: Send + Sync {
    fn now_unix_seconds(&self) -> Result<u64, SessionError>;
}

/// AS inputs with no caller-supplied verification callback.
pub struct SessionBackend<'a> {
    pub verifier_config: Option<VerifierConfig>,
    pub storage: Arc<dyn StorageProvider>,
    pub engine: &'a PolicyEngine<Regorus>,
}

/// An immutable challenge. Returning it again never renews the grant window.
#[derive(Clone)]
pub struct FreshChallenge {
    session_id: String,
    expected_quote: ExpectedGcpLaunchQuote,
    server_nonce: [u8; 32],
}

impl FreshChallenge {
    pub fn server_nonce_hex(&self) -> String {
        hex::encode(self.server_nonce)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn expected_quote(&self) -> &ExpectedGcpLaunchQuote {
        &self.expected_quote
    }
}

/// None of these variants grants permission to fetch or deliver a resource.
pub enum CaptureOutcome {
    Pending,
    Captured(Arc<AppraisedGcpLaunch>),
    /// Exact retry of a completed transcript, including after its live window.
    /// Historical inspection never grants fresh authorization.
    Historical(Arc<AppraisedGcpLaunch>),
}

/// Redacted failures; no submitted evidence, policy, key, or parser error leaks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    InvalidConfig,
    InvalidGrant,
    InvalidKey,
    TooLarge,
    Capacity,
    NotFound,
    Conflict,
    Expired,
    NotYetValid,
    InvalidPossession,
    Rejected,
    VerificationFailed,
    ClockUnavailable,
    ClockOutOfRange,
    ClockRegression,
    StateUnavailable,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "invalid launch session configuration",
            Self::InvalidGrant => "invalid launch session grant",
            Self::InvalidKey => "invalid launch session key representation",
            Self::TooLarge => "launch session input exceeds bounds",
            Self::Capacity => "launch session capacity exhausted",
            Self::NotFound => "launch session not found",
            Self::Conflict => "launch session transcript conflict",
            Self::Expired => "launch session grant expired",
            Self::NotYetValid => "launch session grant is not yet valid",
            Self::InvalidPossession => "launch session recorder possession failed",
            Self::Rejected => "launch session rejected",
            Self::VerificationFailed => "launch session evidence verification failed",
            Self::ClockUnavailable => "launch session clock unavailable",
            Self::ClockOutOfRange => "launch session clock out of range",
            Self::ClockRegression => "launch session clock regressed",
            Self::StateUnavailable => "launch session state unavailable",
        })
    }
}

impl std::error::Error for SessionError {}

#[derive(Eq, Hash, PartialEq)]
struct AttemptKey {
    authority: String,
    tenant: String,
    workload: String,
    role: String,
    attempt: String,
}

impl AttemptKey {
    fn from_grant(grant: &VerifiedLaunchGrant) -> Self {
        let binding = grant.binding();
        Self {
            authority: binding.authority.clone(),
            tenant: binding.tenant.clone(),
            workload: binding.workload_id.clone(),
            role: binding.container_role.clone(),
            attempt: binding.attempt_id.clone(),
        }
    }
}

struct Submission {
    evidence: Arc<[u8]>,
    evidence_sha384: String,
    recorder_public_key: [u8; 32],
    signature: String,
}

impl Submission {
    fn matches(&self, evidence: &[u8], recorder_public_key: &[u8; 32], signature: &str) -> bool {
        self.evidence.as_ref() == evidence
            && self.recorder_public_key == *recorder_public_key
            && self.signature == signature
    }
}

enum EntryStatus {
    Pending,
    Verifying(Arc<Submission>),
    Captured {
        submission: Arc<Submission>,
        appraisal: Arc<AppraisedGcpLaunch>,
    },
    Rejected {
        submission: Option<Arc<Submission>>,
    },
}

struct Entry {
    grant: VerifiedLaunchGrant,
    signed_grant_json: Vec<u8>,
    canonical_key: Vec<u8>,
    challenge: FreshChallenge,
    revision: u64,
    status: EntryStatus,
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    attempts: HashMap<AttemptKey, String>,
    last_seen_unix_seconds: Option<u64>,
}

struct Inner {
    config: SessionConfig,
    clock: Arc<dyn SessionClock>,
    state: Mutex<State>,
}

/// Clones share one atomic state machine. Independent instances do not share it.
#[derive(Clone)]
pub struct FreshLaunchSessions {
    inner: Arc<Inner>,
}

/// Internal snapshot minted only from this instance's completed AS appraisal.
/// It is not a public freshness capability: each new decision rechecks the
/// owning session's current clock/window and this exact captured revision.
#[cfg(feature = "launch-gcp-credentials")]
pub(crate) struct LiveLaunchView {
    session_id: String,
    revision: u64,
    grant_sha384: String,
    authority_key_sha384: String,
    binding: LaunchBinding,
    #[cfg(feature = "launch-gcp-credentials")]
    validity: execution_proof_contract::ValidityWindow,
    expected: ExpectedGcpLaunchQuote,
    appraisal: Arc<AppraisedGcpLaunch>,
}

#[cfg(feature = "launch-gcp-credentials")]
impl LiveLaunchView {
    pub(crate) fn session_id(&self) -> &str {
        &self.session_id
    }
    pub(crate) fn grant_sha384(&self) -> &str {
        &self.grant_sha384
    }
    pub(crate) fn authority_key_sha384(&self) -> &str {
        &self.authority_key_sha384
    }
    pub(crate) fn binding(&self) -> &LaunchBinding {
        &self.binding
    }
    pub(crate) fn expected(&self) -> &ExpectedGcpLaunchQuote {
        &self.expected
    }
    pub(crate) fn appraisal(&self) -> &AppraisedGcpLaunch {
        &self.appraisal
    }
    #[cfg(feature = "launch-gcp-credentials")]
    pub(crate) fn validity(&self) -> &execution_proof_contract::ValidityWindow {
        &self.validity
    }
}

impl FreshLaunchSessions {
    pub fn new(config: SessionConfig, clock: Arc<dyn SessionClock>) -> Result<Self, SessionError> {
        if !(1..=MAX_SESSIONS).contains(&config.capacity)
            || config.selected_policy_id.is_empty()
            || config.selected_policy_id.len() > 128
            || !config
                .selected_policy_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
            || config
                .reference_data
                .as_ref()
                .is_some_and(|data| data.len() > MAX_CAPTURE_OBJECT_BYTES)
        {
            return Err(SessionError::InvalidConfig);
        }
        let binding = config
            .boot_binding
            .digest_sha384()
            .map_err(|_| SessionError::InvalidConfig)?;
        if config.grant_expectations.profile_sha384 != binding {
            return Err(SessionError::InvalidConfig);
        }
        config
            .boot_policy
            .validate()
            .map_err(|_| SessionError::InvalidConfig)?;
        config
            .module_policy
            .validate()
            .map_err(|_| SessionError::InvalidConfig)?;
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                clock,
                state: Mutex::new(State::default()),
            }),
        })
    }

    pub fn boot_binding_sha384(&self) -> String {
        self.inner
            .config
            .boot_binding
            .digest_sha384()
            .expect("validated immutable binding")
    }
    pub(crate) fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// HTTP callers must prove the grant's recorder key before any allocation.
    /// Trusted in-process callers can use `begin` directly.
    pub fn begin_authenticated(
        &self,
        signed_grant_json: &[u8],
        keywrap_public_key: &TeePubKey,
        recorder_public_key: &[u8; 32],
        signature: &str,
    ) -> Result<FreshChallenge, SessionError> {
        if signed_grant_json.len() > MAX_WIRE_BYTES {
            return Err(SessionError::TooLarge);
        }
        let key = canonical_key(keywrap_public_key)?;
        {
            let mut state = self.inner.lock()?;
            let now = self.inner.current_time(&mut state)?;
            let grant = verify_launch_grant(
                signed_grant_json,
                &self.inner.config.grant_expectations,
                now,
            )
            .map_err(map_grant_error)?;
            verify_operation_pop(
                &grant,
                &self.inner.config.boot_binding,
                &SessionOperation::Begin {
                    key_sha384: hash_hex(&key),
                },
                recorder_public_key,
                signature,
            )
            .map_err(|_| SessionError::InvalidPossession)?;
        }
        // Rechecks the trusted clock after lock acquisition; PoP validation did
        // not allocate or reserve an attempt, and a concurrent retry stays exact.
        self.begin(signed_grant_json, keywrap_public_key)
    }

    #[cfg(feature = "launch-gcp-credentials")]
    pub(crate) fn live_resource_view(
        &self,
        session_id: &str,
        operation: &SessionOperation,
        recorder_public_key: &[u8; 32],
        signature: &str,
    ) -> Result<LiveLaunchView, SessionError> {
        let mut state = self.inner.lock()?;
        let entry = state
            .entries
            .get(session_id)
            .ok_or(SessionError::NotFound)?;
        Self::authenticate_resource_operation(
            entry,
            session_id,
            operation,
            recorder_public_key,
            signature,
        )?;
        let now = self.inner.current_time(&mut state)?;
        let entry = state
            .entries
            .get(session_id)
            .ok_or(SessionError::StateUnavailable)?;
        entry
            .grant
            .validity()
            .check_at(now)
            .map_err(map_grant_error)?;
        let EntryStatus::Captured { appraisal, .. } = &entry.status else {
            return Err(SessionError::Rejected);
        };
        Ok(LiveLaunchView {
            session_id: session_id.to_owned(),
            revision: entry.revision,
            grant_sha384: entry.grant.grant_digest().to_owned(),
            authority_key_sha384: entry.grant.authority_key_sha384().to_owned(),
            binding: entry.grant.binding().clone(),
            #[cfg(feature = "launch-gcp-credentials")]
            validity: *entry.grant.validity(),
            expected: entry.challenge.expected_quote.clone(),
            appraisal: appraisal.clone(),
        })
    }

    #[cfg(feature = "launch-gcp-credentials")]
    pub(crate) fn live_resource_challenge_view(
        &self,
        session_id: &str,
        recorder_public_key: &[u8; 32],
        signature: &str,
    ) -> Result<LiveLaunchView, SessionError> {
        let operation = {
            let state = self.inner.lock()?;
            let entry = state
                .entries
                .get(session_id)
                .ok_or(SessionError::NotFound)?;
            let EntryStatus::Captured { submission, .. } = &entry.status else {
                return Err(SessionError::Rejected);
            };
            SessionOperation::ResourceChallenge {
                session_id: session_id.to_owned(),
                nonce: entry.challenge.expected_quote.nonce().to_owned(),
                runtime_sha384: hash_hex(entry.challenge.expected_quote.canonical_runtime()),
                evidence_sha384: submission.evidence_sha384.clone(),
            }
        };
        self.live_resource_view(session_id, &operation, recorder_public_key, signature)
    }

    /// Historical retry authenticates the exact request but deliberately cannot
    /// create a live view, evaluate policy, or refresh an authorization window.
    #[cfg(feature = "launch-gcp-credentials")]
    pub(crate) fn authenticate_resource_retry(
        &self,
        view: &LiveLaunchView,
        operation: &SessionOperation,
        recorder_public_key: &[u8; 32],
        signature: &str,
    ) -> Result<(), SessionError> {
        let state = self.inner.lock()?;
        let entry = state
            .entries
            .get(view.session_id())
            .ok_or(SessionError::NotFound)?;
        Self::check_view(entry, view)?;
        Self::authenticate_resource_operation(
            entry,
            view.session_id(),
            operation,
            recorder_public_key,
            signature,
        )
    }

    #[cfg(feature = "launch-gcp-credentials")]
    pub(crate) fn recheck_live_view(&self, view: &LiveLaunchView) -> Result<(), SessionError> {
        let mut state = self.inner.lock()?;
        let entry = state
            .entries
            .get(view.session_id())
            .ok_or(SessionError::NotFound)?;
        Self::check_view(entry, view)?;
        let now = self.inner.current_time(&mut state)?;
        state
            .entries
            .get(view.session_id())
            .ok_or(SessionError::StateUnavailable)?
            .grant
            .validity()
            .check_at(now)
            .map_err(map_grant_error)
    }

    #[cfg(feature = "launch-gcp-credentials")]
    fn check_view(entry: &Entry, view: &LiveLaunchView) -> Result<(), SessionError> {
        let EntryStatus::Captured { appraisal, .. } = &entry.status else {
            return Err(SessionError::Rejected);
        };
        if entry.revision != view.revision
            || entry.grant.grant_digest() != view.grant_sha384()
            || !Arc::ptr_eq(appraisal, &view.appraisal)
        {
            return Err(SessionError::Conflict);
        }
        Ok(())
    }

    #[cfg(feature = "launch-gcp-credentials")]
    fn authenticate_resource_operation(
        entry: &Entry,
        session_id: &str,
        operation: &SessionOperation,
        recorder_public_key: &[u8; 32],
        signature: &str,
    ) -> Result<(), SessionError> {
        let EntryStatus::Captured { submission, .. } = &entry.status else {
            return Err(SessionError::Rejected);
        };
        let expected = &entry.challenge.expected_quote;
        let (actual_id, nonce, runtime_sha384, evidence_sha384) = match operation {
            SessionOperation::ResourceChallenge {
                session_id,
                nonce,
                runtime_sha384,
                evidence_sha384,
            } => {
                if nonce != expected.nonce() {
                    return Err(SessionError::Conflict);
                }
                (session_id, nonce, runtime_sha384, evidence_sha384)
            }
            SessionOperation::ResourceDecision {
                session_id,
                nonce,
                runtime_sha384,
                evidence_sha384,
                ..
            } => (session_id, nonce, runtime_sha384, evidence_sha384),
            #[cfg(feature = "launch-gcp-credentials")]
            SessionOperation::CredentialDelivery {
                session_id,
                nonce,
                runtime_sha384,
                evidence_sha384,
                ..
            } => (session_id, nonce, runtime_sha384, evidence_sha384),
            #[cfg(not(feature = "launch-gcp-credentials"))]
            SessionOperation::CredentialDelivery { .. } => return Err(SessionError::Conflict),
            SessionOperation::Begin { .. } => return Err(SessionError::Conflict),
        };
        if actual_id != session_id
            || nonce.is_empty()
            || runtime_sha384 != &hash_hex(expected.canonical_runtime())
            || evidence_sha384 != &submission.evidence_sha384
        {
            return Err(SessionError::Conflict);
        }
        verify_operation_pop(
            &entry.grant,
            expected.boot_binding(),
            operation,
            recorder_public_key,
            signature,
        )
        .map_err(|_| SessionError::InvalidPossession)
    }

    #[cfg(test)]
    // Negative-only test targets do not use these shared helpers.
    #[allow(dead_code)]
    pub(crate) fn capture_with_test_appraisal(
        &self,
        session_id: &str,
        evidence: &[u8],
        recorder_public_key: &[u8; 32],
        signature: &str,
        appraisal: AppraisedGcpLaunch,
    ) -> Result<CaptureOutcome, SessionError> {
        let mut started = match self.claim(session_id, evidence, recorder_public_key, signature)? {
            Claim::Started(started) => started,
            Claim::Pending => return Ok(CaptureOutcome::Pending),
            Claim::Historical(appraisal) => return Ok(CaptureOutcome::Historical(appraisal)),
        };
        started
            .guard
            .complete(appraisal, &started.expected, &started.submission)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn start_test_capture(
        &self,
        session_id: &str,
        evidence: &[u8],
        recorder_public_key: &[u8; 32],
        signature: &str,
    ) -> Result<TestCapture, SessionError> {
        match self.claim(session_id, evidence, recorder_public_key, signature)? {
            Claim::Started(started) => Ok(TestCapture { started }),
            Claim::Pending | Claim::Historical(_) => Err(SessionError::Conflict),
        }
    }

    /// Authenticate L against this instance's roots before allocating a session.
    /// One attempt cannot substitute its grant, boot context, or key on retry.
    pub fn begin(
        &self,
        signed_grant_json: &[u8],
        keywrap_public_key: &TeePubKey,
    ) -> Result<FreshChallenge, SessionError> {
        if signed_grant_json.len() > MAX_WIRE_BYTES {
            return Err(SessionError::TooLarge);
        }
        let canonical_key = canonical_key(keywrap_public_key)?;
        let mut state = self.inner.lock()?;
        let now = self.inner.current_time(&mut state)?;
        let grant = verify_launch_grant(
            signed_grant_json,
            &self.inner.config.grant_expectations,
            now,
        )
        .map_err(map_grant_error)?;
        let attempt = AttemptKey::from_grant(&grant);
        if let Some(session_id) = state.attempts.get(&attempt) {
            let entry = state
                .entries
                .get(session_id)
                .ok_or(SessionError::StateUnavailable)?;
            if entry.signed_grant_json != signed_grant_json || entry.canonical_key != canonical_key
            {
                return Err(SessionError::Conflict);
            }
            if matches!(entry.status, EntryStatus::Rejected { .. }) {
                return Err(SessionError::Rejected);
            }
            return Ok(entry.challenge.clone());
        }
        // Tombstones are retained: no expiry/eviction silently permits a second
        // transcript for an attempt within this process lifetime.
        if state.entries.len() >= self.inner.config.capacity {
            return Err(SessionError::Capacity);
        }
        let random = ring::rand::SystemRandom::new();
        let mut nonce = [0_u8; 32];
        let mut session_id_bytes = [0_u8; 32];
        random
            .fill(&mut nonce)
            .and_then(|_| random.fill(&mut session_id_bytes))
            .map_err(|_| SessionError::StateUnavailable)?;
        let session_id = hex::encode(session_id_bytes);
        if state.entries.contains_key(&session_id) {
            return Err(SessionError::Conflict);
        }
        let expected_quote = ExpectedGcpLaunchQuote::new(
            &grant,
            self.inner.config.boot_binding.clone(),
            nonce,
            keywrap_public_key,
            self.inner.config.boot_policy.clone(),
            self.inner.config.module_policy.clone(),
        )
        .map_err(|_| SessionError::InvalidKey)?;
        let challenge = FreshChallenge {
            session_id: session_id.clone(),
            expected_quote,
            server_nonce: nonce,
        };
        state.attempts.insert(attempt, session_id.clone());
        state.entries.insert(
            session_id,
            Entry {
                grant,
                signed_grant_json: signed_grant_json.to_vec(),
                canonical_key,
                challenge: challenge.clone(),
                revision: 0,
                status: EntryStatus::Pending,
            },
        );
        Ok(challenge)
    }

    /// Authenticate recorder possession before claiming the evidence transcript.
    /// Only the AS factory can produce a new completed appraisal here.
    pub async fn capture(
        &self,
        session_id: &str,
        evidence: &[u8],
        recorder_public_key: &[u8; 32],
        signature: &str,
        backend: SessionBackend<'_>,
    ) -> Result<CaptureOutcome, SessionError> {
        let claim = self.claim(session_id, evidence, recorder_public_key, signature)?;
        let mut started = match claim {
            Claim::Started(started) => started,
            Claim::Pending => return Ok(CaptureOutcome::Pending),
            Claim::Historical(appraisal) => return Ok(CaptureOutcome::Historical(appraisal)),
        };
        let appraisal = appraise_gcp_launch_quote(
            started.expected.clone(),
            &started.submission.evidence,
            backend.verifier_config,
            backend.storage,
            backend.engine,
            &self.inner.config.selected_policy_id,
            self.inner.config.reference_data.as_deref(),
        )
        .await
        .map_err(|_| SessionError::VerificationFailed)?;
        started
            .guard
            .complete(appraisal, &started.expected, &started.submission)
    }

    /// Abort invalidates an in-flight revision, including a late AS completion.
    /// This is denial only; it does not mint a replacement session or nonce.
    pub fn abort(&self, session_id: &str) -> Result<(), SessionError> {
        let mut state = self.inner.lock()?;
        let entry = state
            .entries
            .get_mut(session_id)
            .ok_or(SessionError::NotFound)?;
        // Abort denies pending work and retains completed transcripts for exact retry.
        if matches!(entry.status, EntryStatus::Captured { .. }) {
            return Err(SessionError::Conflict);
        }
        if matches!(entry.status, EntryStatus::Rejected { .. }) {
            return Ok(());
        }
        entry.revision = entry
            .revision
            .checked_add(1)
            .ok_or(SessionError::StateUnavailable)?;
        let submission = match &entry.status {
            EntryStatus::Verifying(submission) | EntryStatus::Captured { submission, .. } => {
                Some(submission.clone())
            }
            EntryStatus::Rejected { submission } => submission.clone(),
            EntryStatus::Pending => None,
        };
        entry.status = EntryStatus::Rejected { submission };
        Ok(())
    }

    /// Explicit access to potentially confidential exact evidence bytes. These
    /// bytes are not themselves verified claims or authorization credentials.
    pub fn evidence_bytes(&self, session_id: &str) -> Result<Option<Arc<[u8]>>, SessionError> {
        let state = self.inner.lock()?;
        let entry = state
            .entries
            .get(session_id)
            .ok_or(SessionError::NotFound)?;
        Ok(match &entry.status {
            EntryStatus::Verifying(submission) | EntryStatus::Captured { submission, .. } => {
                Some(submission.evidence.clone())
            }
            EntryStatus::Rejected { submission } => submission
                .as_ref()
                .map(|submission| submission.evidence.clone()),
            EntryStatus::Pending => None,
        })
    }

    fn claim(
        &self,
        session_id: &str,
        evidence: &[u8],
        recorder_public_key: &[u8; 32],
        signature: &str,
    ) -> Result<Claim, SessionError> {
        if evidence.is_empty() || evidence.len() > MAX_SESSION_EVIDENCE_BYTES {
            return Err(SessionError::TooLarge);
        }
        if signature.len() != 128 {
            return Err(SessionError::InvalidPossession);
        }
        let evidence_sha384 = hex::encode(digest::digest(&digest::SHA384, evidence));
        let mut state = self.inner.lock()?;
        let entry = state
            .entries
            .get(session_id)
            .ok_or(SessionError::NotFound)?;
        let expected = &entry.challenge.expected_quote;
        verify_recorder_session_pop(
            &entry.grant,
            expected.boot_binding(),
            expected.nonce(),
            &hash_hex(expected.canonical_runtime()),
            &evidence_sha384,
            recorder_public_key,
            signature,
        )
        .map_err(|_| SessionError::InvalidPossession)?;
        match &entry.status {
            EntryStatus::Verifying(submission) => {
                return if submission.matches(evidence, recorder_public_key, signature) {
                    Ok(Claim::Pending)
                } else {
                    Err(SessionError::Conflict)
                };
            }
            EntryStatus::Captured {
                submission,
                appraisal,
            } => {
                return if submission.matches(evidence, recorder_public_key, signature) {
                    Ok(Claim::Historical(appraisal.clone()))
                } else {
                    Err(SessionError::Conflict)
                };
            }
            EntryStatus::Rejected { .. } => return Err(SessionError::Rejected),
            EntryStatus::Pending => {}
        }
        let now = self.inner.current_time(&mut state)?;
        let entry = state
            .entries
            .get_mut(session_id)
            .ok_or(SessionError::StateUnavailable)?;
        entry
            .grant
            .validity()
            .check_at(now)
            .map_err(map_grant_error)?;
        let revision = entry
            .revision
            .checked_add(1)
            .ok_or(SessionError::StateUnavailable)?;
        let submission = Arc::new(Submission {
            evidence: Arc::from(evidence),
            evidence_sha384,
            recorder_public_key: *recorder_public_key,
            signature: signature.to_owned(),
        });
        entry.revision = revision;
        entry.status = EntryStatus::Verifying(submission.clone());
        Ok(Claim::Started(Box::new(StartedVerification {
            guard: VerificationGuard {
                inner: self.inner.clone(),
                session_id: session_id.to_owned(),
                revision,
                active: true,
            },
            expected: entry.challenge.expected_quote.clone(),
            submission,
        })))
    }
}

impl Inner {
    fn lock(&self) -> Result<MutexGuard<'_, State>, SessionError> {
        self.state
            .lock()
            .map_err(|_| SessionError::StateUnavailable)
    }

    fn current_time(&self, state: &mut State) -> Result<u64, SessionError> {
        let now = self.clock.now_unix_seconds()?;
        if now > i64::MAX as u64 {
            return Err(SessionError::ClockOutOfRange);
        }
        if state.last_seen_unix_seconds.is_some_and(|last| now < last) {
            return Err(SessionError::ClockRegression);
        }
        state.last_seen_unix_seconds = Some(now);
        Ok(now)
    }
}

enum Claim {
    Started(Box<StartedVerification>),
    Pending,
    Historical(Arc<AppraisedGcpLaunch>),
}

struct StartedVerification {
    guard: VerificationGuard,
    expected: ExpectedGcpLaunchQuote,
    submission: Arc<Submission>,
}

/// Test-only in-flight claim, excluded from normal builds. It cannot construct
/// an AS appraisal; dropping it exercises the session cancellation path.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) struct TestCapture {
    started: Box<StartedVerification>,
}

#[cfg(test)]
#[allow(dead_code)]
impl TestCapture {
    pub(crate) fn complete(
        mut self,
        appraisal: AppraisedGcpLaunch,
    ) -> Result<CaptureOutcome, SessionError> {
        self.started
            .guard
            .complete(appraisal, &self.started.expected, &self.started.submission)
    }
}

struct VerificationGuard {
    inner: Arc<Inner>,
    session_id: String,
    revision: u64,
    active: bool,
}

impl VerificationGuard {
    fn complete(
        &mut self,
        appraisal: AppraisedGcpLaunch,
        expected: &ExpectedGcpLaunchQuote,
        submission: &Submission,
    ) -> Result<CaptureOutcome, SessionError> {
        let actual = appraisal.evidence();
        let actual_expected = actual.expected();
        if actual.evidence_sha384() != submission.evidence_sha384
            || actual_expected.nonce() != expected.nonce()
            || actual_expected.grant_digest() != expected.grant_digest()
            || actual_expected.report_data() != expected.report_data()
            || actual_expected.canonical_runtime() != expected.canonical_runtime()
            || actual_expected.boot_binding() != expected.boot_binding()
            || actual_expected.launch_policy_sha384() != expected.launch_policy_sha384()
            || appraisal.policy().capture().actual_policy_id()
                != self.inner.config.selected_policy_id
            || appraisal.policy().capture().policy_commitment().sha384()
                != expected.launch_policy_sha384()
            || appraisal.policy().capture().data_bytes()
                != self
                    .inner
                    .config
                    .reference_data
                    .as_deref()
                    .map(str::as_bytes)
        {
            return Err(SessionError::Conflict);
        }
        let mut state = self.inner.lock()?;
        let entry = state
            .entries
            .get(&self.session_id)
            .ok_or(SessionError::NotFound)?;
        if entry.revision != self.revision || !matches!(entry.status, EntryStatus::Verifying(_)) {
            return Err(SessionError::Conflict);
        }
        let now = self.inner.current_time(&mut state)?;
        let entry = state
            .entries
            .get_mut(&self.session_id)
            .ok_or(SessionError::StateUnavailable)?;
        entry
            .grant
            .validity()
            .check_at(now)
            .map_err(map_grant_error)?;
        let EntryStatus::Verifying(bound_submission) = &entry.status else {
            return Err(SessionError::Conflict);
        };
        if !bound_submission.matches(
            &submission.evidence,
            &submission.recorder_public_key,
            &submission.signature,
        ) {
            return Err(SessionError::Conflict);
        }
        let appraisal = Arc::new(appraisal);
        entry.status = EntryStatus::Captured {
            submission: bound_submission.clone(),
            appraisal: appraisal.clone(),
        };
        self.active = false;
        Ok(CaptureOutcome::Captured(appraisal))
    }
}

impl Drop for VerificationGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // No await in Drop. Poisoning also fails closed: every future operation
        // rejects access to this state rather than recovering a partial write.
        if let Ok(mut state) = self.inner.state.lock() {
            if let Some(entry) = state.entries.get_mut(&self.session_id) {
                if entry.revision == self.revision
                    && matches!(entry.status, EntryStatus::Verifying(_))
                {
                    let EntryStatus::Verifying(submission) = &entry.status else {
                        return;
                    };
                    entry.status = EntryStatus::Rejected {
                        submission: Some(submission.clone()),
                    };
                }
            }
        }
    }
}

fn canonical_key(key: &TeePubKey) -> Result<Vec<u8>, SessionError> {
    let fields: &[&str] = match key {
        TeePubKey::RSA { alg, k_mod, k_exp } => &[alg, k_mod, k_exp],
        TeePubKey::EC { crv, alg, x, y } => &[crv, alg, x, y],
    };
    let length = fields
        .iter()
        .try_fold(0_usize, |length, field| length.checked_add(field.len()));
    if length.is_none_or(|length| length > MAX_WIRE_BYTES) {
        return Err(SessionError::TooLarge);
    }
    let bytes = serde_json_canonicalizer::to_vec(key).map_err(|_| SessionError::InvalidKey)?;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(SessionError::TooLarge);
    }
    Ok(bytes)
}

fn hash_hex(bytes: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA384, bytes))
}

fn map_grant_error(error: execution_proof_contract::Error) -> SessionError {
    match error {
        execution_proof_contract::Error::Expired => SessionError::Expired,
        execution_proof_contract::Error::NotYetValid => SessionError::NotYetValid,
        execution_proof_contract::Error::InvalidTime => SessionError::ClockOutOfRange,
        _ => SessionError::InvalidGrant,
    }
}
