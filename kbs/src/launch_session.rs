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
    launch_evidence::{appraise_launch_quote, AppraisedLaunch, ExpectedLaunchQuote},
};
#[cfg(feature = "launch-http")]
use execution_proof_contract::LaunchBinding;
use execution_proof_contract::{
    session::{verify_operation_pop, verify_recorder_session_pop, SessionOperation},
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

pub const MAX_SESSION_EVIDENCE_BYTES: usize = 1024 * 1024;
pub const MAX_SESSIONS: usize = 1024;

/// Trusted configuration, selected by the embedding server, never by a request.
/// No raw Debug/serde is provided for policy or reference data.
pub struct SessionConfig {
    pub grant_expectations: GrantExpectations,
    pub expected_init_data_sha384: [u8; 48],
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
    expected_quote: ExpectedLaunchQuote,
}

impl FreshChallenge {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn expected_quote(&self) -> &ExpectedLaunchQuote {
        &self.expected_quote
    }
}

/// None of these variants grants permission to fetch or deliver a resource.
pub enum CaptureOutcome {
    Pending,
    Captured(Arc<AppraisedLaunch>),
    /// Exact retry of a completed transcript, including after its live window.
    /// Historical inspection never grants fresh authorization.
    Historical(Arc<AppraisedLaunch>),
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
        appraisal: Arc<AppraisedLaunch>,
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
#[cfg(feature = "launch-http")]
pub(crate) struct LiveLaunchView {
    session_id: String,
    revision: u64,
    grant_sha384: String,
    authority_key_sha384: String,
    binding: LaunchBinding,
    #[cfg(feature = "launch-credentials")]
    validity: execution_proof_contract::ValidityWindow,
    expected: ExpectedLaunchQuote,
    appraisal: Arc<AppraisedLaunch>,
}

#[cfg(feature = "launch-http")]
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
    pub(crate) fn expected(&self) -> &ExpectedLaunchQuote {
        &self.expected
    }
    pub(crate) fn appraisal(&self) -> &AppraisedLaunch {
        &self.appraisal
    }
    #[cfg(feature = "launch-credentials")]
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
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                clock,
                state: Mutex::new(State::default()),
            }),
        })
    }

    /// HTTP callers must prove the grant's recorder key before any allocation.
    /// The trusted in-process `begin` API remains available for existing users.
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

    #[cfg(feature = "launch-http")]
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
            #[cfg(feature = "launch-credentials")]
            validity: *entry.grant.validity(),
            expected: entry.challenge.expected_quote.clone(),
            appraisal: appraisal.clone(),
        })
    }

    #[cfg(feature = "launch-http")]
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
                runtime_sha384: hex::encode(entry.challenge.expected_quote.report_data()),
                evidence_sha384: submission.evidence_sha384.clone(),
            }
        };
        self.live_resource_view(session_id, &operation, recorder_public_key, signature)
    }

    /// Historical retry authenticates the exact request but deliberately cannot
    /// create a live view, evaluate policy, or refresh an authorization window.
    #[cfg(feature = "launch-http")]
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

    #[cfg(feature = "launch-http")]
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

    #[cfg(feature = "launch-http")]
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

    #[cfg(feature = "launch-http")]
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
            #[cfg(feature = "launch-credentials")]
            SessionOperation::CredentialDelivery {
                session_id,
                nonce,
                runtime_sha384,
                evidence_sha384,
                ..
            } => (session_id, nonce, runtime_sha384, evidence_sha384),
            #[cfg(not(feature = "launch-credentials"))]
            SessionOperation::CredentialDelivery { .. } => return Err(SessionError::Conflict),
            SessionOperation::Begin { .. } => return Err(SessionError::Conflict),
        };
        if actual_id != session_id
            || nonce.is_empty()
            || runtime_sha384 != &hex::encode(expected.report_data())
            || evidence_sha384 != &submission.evidence_sha384
        {
            return Err(SessionError::Conflict);
        }
        verify_operation_pop(&entry.grant, operation, recorder_public_key, signature)
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
        appraisal: AppraisedLaunch,
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
        let expected_quote = ExpectedLaunchQuote::new(
            &grant,
            nonce,
            keywrap_public_key,
            self.inner.config.expected_init_data_sha384,
        )
        .map_err(|_| SessionError::InvalidKey)?;
        let challenge = FreshChallenge {
            session_id: session_id.clone(),
            expected_quote,
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
        let appraisal = appraise_launch_quote(
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
            expected.nonce(),
            &hex::encode(expected.report_data()),
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
    Historical(Arc<AppraisedLaunch>),
}

struct StartedVerification {
    guard: VerificationGuard,
    expected: ExpectedLaunchQuote,
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
        appraisal: AppraisedLaunch,
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
        appraisal: AppraisedLaunch,
        expected: &ExpectedLaunchQuote,
        submission: &Submission,
    ) -> Result<CaptureOutcome, SessionError> {
        let actual = appraisal.evidence();
        let actual_expected = actual.expected();
        if actual.evidence_sha384() != submission.evidence_sha384
            || actual_expected.nonce() != expected.nonce()
            || actual_expected.grant_digest() != expected.grant_digest()
            || actual_expected.report_data() != expected.report_data()
            || actual_expected.canonical_runtime() != expected.canonical_runtime()
            || actual_expected.init_data() != expected.init_data()
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

#[cfg(test)]
mod tests {
    use super::*;
    use execution_proof_contract::{
        session::recorder_session_signing_bytes, LaunchBinding, LaunchGrant, Signed,
        ValidityWindow, GRANT_PURPOSE, VERSION,
    };
    use key_value_storage::{
        memory::MemoryKeyValueStorage, KvStorageProvider, StorageBackendConfig,
    };
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::{sync::Barrier, thread};

    struct ManualClock(Mutex<Result<u64, SessionError>>);

    impl ManualClock {
        fn set(&self, now: Result<u64, SessionError>) {
            *self.0.lock().unwrap() = now;
        }
    }

    impl SessionClock for ManualClock {
        fn now_unix_seconds(&self) -> Result<u64, SessionError> {
            *self.0.lock().unwrap()
        }
    }

    struct Fixture {
        sessions: FreshLaunchSessions,
        clock: Arc<ManualClock>,
        authority: Ed25519KeyPair,
        recorder: Ed25519KeyPair,
        grant: LaunchGrant,
        wire: Vec<u8>,
        keywrap: TeePubKey,
    }

    fn key() -> Ed25519KeyPair {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn signed(grant: &LaunchGrant, signer: &Ed25519KeyPair) -> Vec<u8> {
        serde_json::to_vec(&Signed {
            statement: grant.clone(),
            signature: hex::encode(signer.sign(&grant.signing_bytes().unwrap()).as_ref()),
        })
        .unwrap()
    }

    fn fixture(capacity: usize) -> Fixture {
        let authority = key();
        let recorder = key();
        let grant = LaunchGrant {
            version: VERSION,
            purpose: GRANT_PURPOSE.into(),
            audience: "fresh-session-fixture".into(),
            proof_required: true,
            grant_id: "grant-1".into(),
            validity: ValidityWindow {
                not_before: 900,
                expires: 1030,
            },
            binding: LaunchBinding {
                authority: "authority-1".into(),
                tenant: "tenant-1".into(),
                workload_id: "workload-1".into(),
                container_role: "application-init".into(),
                attempt_id: "attempt-1".into(),
                boot_id: "boot-1".into(),
                channel_key_sha384: hex::encode(digest::digest(
                    &digest::SHA384,
                    recorder.public_key().as_ref(),
                )),
                bootstrap_context_sha384: "11".repeat(48),
                selected_manifest_sha256: "12".repeat(32),
                effective_launch_sha384: "13".repeat(48),
                profile_sha384: "14".repeat(48),
                launch_policy_sha384: "15".repeat(48),
                image_policy_sha384: "16".repeat(48),
                challenge_sha384: "17".repeat(48),
            },
        };
        let wire = signed(&grant, &authority);
        let config = SessionConfig {
            grant_expectations: GrantExpectations {
                authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
                audience: grant.audience.clone(),
                authority: grant.binding.authority.clone(),
                tenant: grant.binding.tenant.clone(),
                profile_sha384: grant.binding.profile_sha384.clone(),
                launch_policy_sha384: grant.binding.launch_policy_sha384.clone(),
                image_policy_sha384: grant.binding.image_policy_sha384.clone(),
            },
            expected_init_data_sha384: [0x21; 48],
            selected_policy_id: "launch_cpu".into(),
            reference_data: None,
            capacity,
        };
        let clock = Arc::new(ManualClock(Mutex::new(Ok(1000))));
        let sessions = FreshLaunchSessions::new(config, clock.clone()).unwrap();
        Fixture {
            sessions,
            clock,
            authority,
            recorder,
            grant,
            wire,
            // Only a runtime-data key commitment fixture, never a usable key.
            keywrap: TeePubKey::RSA {
                alg: "RSA-OAEP-256".into(),
                k_mod: "fixture-modulus".into(),
                k_exp: "AQAB".into(),
            },
        }
    }

    impl Fixture {
        fn possession(&self, challenge: &FreshChallenge, evidence: &[u8]) -> ([u8; 32], String) {
            let grant = verify_launch_grant(
                &self.wire,
                &self.sessions.inner.config.grant_expectations,
                1000,
            )
            .unwrap();
            let bytes = recorder_session_signing_bytes(
                &grant,
                challenge.expected_quote().nonce(),
                &hex::encode(challenge.expected_quote().report_data()),
                &hex::encode(digest::digest(&digest::SHA384, evidence)),
            )
            .unwrap();
            (
                self.recorder.public_key().as_ref().try_into().unwrap(),
                hex::encode(self.recorder.sign(&bytes).as_ref()),
            )
        }
    }

    #[test]
    fn exact_begin_retry_never_renews_or_substitutes_the_attempt() {
        let f = fixture(4);
        let first = f.sessions.begin(&f.wire, &f.keywrap).unwrap();
        f.clock.set(Ok(1029));
        let retry = f.sessions.begin(&f.wire, &f.keywrap).unwrap();
        assert_eq!(first.session_id(), retry.session_id());
        assert_eq!(
            first.expected_quote().nonce(),
            retry.expected_quote().nonce()
        );
        assert_eq!(
            first.expected_quote().canonical_runtime(),
            retry.expected_quote().canonical_runtime()
        );
        let mut replacement = f.grant.clone();
        replacement.binding.boot_id = "another-boot".into();
        assert_eq!(
            f.sessions
                .begin(&signed(&replacement, &f.authority), &f.keywrap)
                .err(),
            Some(SessionError::Conflict)
        );
        let changed_key = TeePubKey::RSA {
            alg: "RSA-OAEP-256".into(),
            k_mod: "other-modulus".into(),
            k_exp: "AQAB".into(),
        };
        assert_eq!(
            f.sessions.begin(&f.wire, &changed_key).err(),
            Some(SessionError::Conflict)
        );
        f.clock.set(Ok(1030));
        assert_eq!(
            f.sessions.begin(&f.wire, &f.keywrap).err(),
            Some(SessionError::Expired)
        );
        f.clock.set(Ok(1029));
        assert_eq!(
            f.sessions.begin(&f.wire, &f.keywrap).err(),
            Some(SessionError::ClockRegression)
        );
    }

    #[test]
    fn pinned_authority_and_scope_are_checked_before_allocating() {
        let f = fixture(2);
        assert_eq!(
            f.sessions
                .begin(&signed(&f.grant, &key()), &f.keywrap)
                .err(),
            Some(SessionError::InvalidGrant)
        );
        let mut changed = f.grant.clone();
        changed.binding.tenant = "other-tenant".into();
        assert_eq!(
            f.sessions
                .begin(&signed(&changed, &f.authority), &f.keywrap)
                .err(),
            Some(SessionError::InvalidGrant)
        );
        changed = f.grant.clone();
        changed.proof_required = false;
        assert_eq!(
            f.sessions
                .begin(&signed(&changed, &f.authority), &f.keywrap)
                .err(),
            Some(SessionError::InvalidGrant)
        );
        assert!(f.sessions.inner.lock().unwrap().entries.is_empty());
    }

    #[test]
    fn possession_precedes_claim_and_cancellation_keeps_a_rejected_tombstone() {
        let f = fixture(2);
        let challenge = f.sessions.begin(&f.wire, &f.keywrap).unwrap();
        let evidence = b"{\n\"quote\":\"software-fixture-only\"}";
        let (recorder, signature) = f.possession(&challenge, evidence);
        assert_eq!(
            f.sessions
                .claim(
                    challenge.session_id(),
                    evidence,
                    &recorder,
                    &"00".repeat(64)
                )
                .err(),
            Some(SessionError::InvalidPossession)
        );
        assert!(f
            .sessions
            .evidence_bytes(challenge.session_id())
            .unwrap()
            .is_none());
        let claim = f
            .sessions
            .claim(challenge.session_id(), evidence, &recorder, &signature)
            .unwrap();
        assert!(matches!(claim, Claim::Started(_)));
        assert!(matches!(
            f.sessions
                .claim(challenge.session_id(), evidence, &recorder, &signature)
                .unwrap(),
            Claim::Pending
        ));
        let other_evidence = b"{\"quote\":\"different-fixture\"}";
        let (_, other_signature) = f.possession(&challenge, other_evidence);
        assert_eq!(
            f.sessions
                .claim(
                    challenge.session_id(),
                    other_evidence,
                    &recorder,
                    &other_signature
                )
                .err(),
            Some(SessionError::Conflict)
        );
        drop(claim); // The same production RAII path used when a capture future is cancelled.
        assert_eq!(
            f.sessions
                .claim(challenge.session_id(), evidence, &recorder, &signature)
                .err(),
            Some(SessionError::Rejected)
        );
        assert_eq!(
            f.sessions
                .evidence_bytes(challenge.session_id())
                .unwrap()
                .unwrap()
                .as_ref(),
            evidence
        );
        assert_eq!(
            f.sessions.begin(&f.wire, &f.keywrap).err(),
            Some(SessionError::Rejected)
        );
    }

    #[test]
    fn concurrent_clones_claim_only_one_revision_and_abort_invalidates_it() {
        let f = fixture(2);
        let challenge = f.sessions.begin(&f.wire, &f.keywrap).unwrap();
        let evidence = b"{\"quote\":\"software-fixture\"}";
        let (recorder, signature) = f.possession(&challenge, evidence);
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let sessions = f.sessions.clone();
                let session_id = challenge.session_id().to_owned();
                let signature = signature.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    sessions.claim(&session_id, evidence, &recorder, &signature)
                })
            })
            .collect();
        let claims: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect();
        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, Claim::Started(_)))
                .count(),
            1
        );
        assert_eq!(
            claims
                .iter()
                .filter(|claim| matches!(claim, Claim::Pending))
                .count(),
            1
        );
        f.sessions.abort(challenge.session_id()).unwrap();
        drop(claims);
        assert_eq!(
            f.sessions
                .claim(challenge.session_id(), evidence, &recorder, &signature)
                .err(),
            Some(SessionError::Rejected)
        );
    }

    #[test]
    fn clock_errors_and_capacity_do_not_allocate_or_recycle_attempts() {
        let f = fixture(1);
        f.clock.set(Err(SessionError::ClockUnavailable));
        assert_eq!(
            f.sessions.begin(&f.wire, &f.keywrap).err(),
            Some(SessionError::ClockUnavailable)
        );
        f.clock.set(Ok(u64::MAX));
        assert_eq!(
            f.sessions.begin(&f.wire, &f.keywrap).err(),
            Some(SessionError::ClockOutOfRange)
        );
        assert!(f.sessions.inner.lock().unwrap().entries.is_empty());
        f.clock.set(Ok(1000));
        let challenge = f.sessions.begin(&f.wire, &f.keywrap).unwrap();
        f.sessions.abort(challenge.session_id()).unwrap();
        let mut next_attempt = f.grant.clone();
        next_attempt.binding.attempt_id = "attempt-2".into();
        assert_eq!(
            f.sessions
                .begin(&signed(&next_attempt, &f.authority), &f.keywrap)
                .err(),
            Some(SessionError::Capacity)
        );
        assert_eq!(f.sessions.inner.lock().unwrap().entries.len(), 1);
    }

    #[tokio::test]
    async fn public_capture_dispatches_to_actual_tdx_factory_without_sample_fallback() {
        let f = fixture(1);
        let challenge = f.sessions.begin(&f.wire, &f.keywrap).unwrap();
        // Valid object syntax reaches TDX factory dispatch. This test workspace
        // enables no TDX backend and exposes no sample or caller callback.
        let evidence = b"{}";
        let (recorder, signature) = f.possession(&challenge, evidence);
        let engine = PolicyEngine::<Regorus>::new(Arc::new(MemoryKeyValueStorage::default()));
        let result = f
            .sessions
            .capture(
                challenge.session_id(),
                evidence,
                &recorder,
                &signature,
                SessionBackend {
                    verifier_config: None,
                    storage: KvStorageProvider::new(StorageBackendConfig::default()),
                    engine: &engine,
                },
            )
            .await;
        assert_eq!(result.err(), Some(SessionError::VerificationFailed));
        assert_eq!(
            f.sessions
                .claim(challenge.session_id(), evidence, &recorder, &signature)
                .err(),
            Some(SessionError::Rejected)
        );
    }
}
