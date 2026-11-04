// SPDX-License-Identifier: Apache-2.0

//! Authenticated, policy-only decisions for one captured launch session.
//!
//! Claims come only from the owning session's AS appraisal. This path uses no
//! legacy token, caller claims JSON, resource plugin, secret fetch, or JWE.
//! The signed aggregate authenticates the combined AS/KBS policy facts and
//! confers no access token or complete launch/execution proof.

use crate::{
    launch_policy::evaluate_kbs_policy,
    launch_session::{FreshLaunchSessions, LiveLaunchView, SessionError, MAX_SESSIONS},
};
use execution_proof_contract::{
    policy_receipt::{
        LaunchPolicyAggregateV1, PolicyCommitments, ResourcePolicyRequest,
        POLICY_AGGREGATE_PROFILE, POLICY_AGGREGATE_PURPOSE, POLICY_AGGREGATE_VERSION,
    },
    session::SessionOperation,
    Signed, MAX_WIRE_BYTES,
};
use policy_engine::{capture::CapturedEvaluation, rego::Regorus, PolicyEngine};
use ring::{
    digest,
    rand::SecureRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use serde_json::json;
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

pub const RESOURCE_INPUT_PROFILE: &str = "onb17.verified-launch-resource-input.v1";

/// Selected by the embedding server. The dedicated proof key must not be
/// registered with legacy access-token verifiers. No raw Debug/serde is exposed.
pub struct LaunchResourceConfig {
    pub sessions: FreshLaunchSessions,
    pub engine: PolicyEngine<Regorus>,
    pub policy_id: String,
    pub policy_sha384: String,
    pub signer: Ed25519KeyPair,
    pub audience: String,
    pub issuer: String,
    pub profile: String,
    pub capacity: usize,
}

#[derive(Clone)]
pub struct ResourceChallenge {
    session_id: String,
    nonce: String,
    grant_sha384: String,
    runtime_sha384: String,
    evidence_sha384: String,
    init_data_sha384: String,
    recorder_key_sha384: String,
}

impl ResourceChallenge {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn grant_sha384(&self) -> &str {
        &self.grant_sha384
    }
    pub fn runtime_sha384(&self) -> &str {
        &self.runtime_sha384
    }
    pub fn evidence_sha384(&self) -> &str {
        &self.evidence_sha384
    }
    pub fn init_data_sha384(&self) -> &str {
        &self.init_data_sha384
    }
    pub fn recorder_key_sha384(&self) -> &str {
        &self.recorder_key_sha384
    }
}

/// Every returned artifact is policy-only. Historical bytes cannot authorize
/// another evaluation or action, even if the caller retains them after expiry.
pub enum ResourceOutcome {
    Pending,
    Current(Arc<[u8]>),
    Historical(Arc<[u8]>),
}

/// Private provenance from this service's completed policy decision. It is not
/// constructible from an aggregate supplied by a request or a caller boolean.
#[cfg(feature = "launch-credentials")]
pub(crate) struct CompletedCredentialPolicy {
    owner: Arc<Inner>,
    view: Arc<LiveLaunchView>,
    request: ResourcePolicyRequest,
    aggregate: Arc<[u8]>,
    aggregate_sha384: String,
}

#[cfg(feature = "launch-credentials")]
impl CompletedCredentialPolicy {
    pub(crate) fn view(&self) -> &LiveLaunchView {
        &self.view
    }
    pub(crate) fn request(&self) -> &ResourcePolicyRequest {
        &self.request
    }
    pub(crate) fn aggregate_sha384(&self) -> &str {
        &self.aggregate_sha384
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceError {
    InvalidConfig,
    InvalidRequest,
    Session(SessionError),
    InvalidPossession,
    NotFound,
    Conflict,
    Capacity,
    Rejected,
    PolicyDenied,
    PolicyMismatch,
    Internal,
}

impl fmt::Display for ResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidConfig => "invalid launch resource configuration",
            Self::InvalidRequest => "invalid launch resource policy request",
            Self::Session(_) => "launch resource session check failed",
            Self::InvalidPossession => "launch resource recorder possession failed",
            Self::NotFound => "launch resource challenge not found",
            Self::Conflict => "launch resource transcript conflict",
            Self::Capacity => "launch resource capacity exhausted",
            Self::Rejected => "launch resource request rejected",
            Self::PolicyDenied => "launch resource policy did not allow the request",
            Self::PolicyMismatch => "launch resource policy differs from configured policy",
            Self::Internal => "launch resource state unavailable",
        })
    }
}

impl std::error::Error for ResourceError {}

impl From<SessionError> for ResourceError {
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::InvalidPossession => Self::InvalidPossession,
            other => Self::Session(other),
        }
    }
}

struct SubmittedRequest {
    request: ResourcePolicyRequest,
    recorder_public_key: [u8; 32],
    signature: String,
}

impl SubmittedRequest {
    fn matches(
        &self,
        request: &ResourcePolicyRequest,
        public_key: &[u8; 32],
        signature: &str,
    ) -> bool {
        &self.request == request
            && self.recorder_public_key == *public_key
            && self.signature == signature
    }
}

enum RequestStatus {
    Ready,
    Evaluating(Arc<SubmittedRequest>),
    Complete {
        request: Arc<SubmittedRequest>,
        signed_bytes: Arc<[u8]>,
    },
    Rejected,
}

struct ResourceEntry {
    view: Arc<LiveLaunchView>,
    challenge: ResourceChallenge,
    revision: u64,
    status: RequestStatus,
}

struct Inner {
    config: LaunchResourceConfig,
    signer_sha384: String,
    entries: Mutex<HashMap<String, ResourceEntry>>,
}

/// Clones share one ephemeral, bounded request slot per captured session.
#[derive(Clone)]
pub struct LaunchResourceService {
    inner: Arc<Inner>,
}

impl LaunchResourceService {
    pub fn new(config: LaunchResourceConfig) -> Result<Self, ResourceError> {
        if !(1..=MAX_SESSIONS).contains(&config.capacity)
            || !policy_id(&config.policy_id)
            // The legacy default uses an EAR-shaped input, not this schema.
            || config.policy_id == "resource-policy"
            || !hash(&config.policy_sha384)
            || !identifier(&config.audience)
            || !identifier(&config.issuer)
            || config.profile != POLICY_AGGREGATE_PROFILE
        {
            return Err(ResourceError::InvalidConfig);
        }
        let signer_sha384 = hash_hex(config.signer.public_key().as_ref());
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                signer_sha384,
                entries: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub fn sessions(&self) -> &FreshLaunchSessions {
        &self.inner.config.sessions
    }

    #[cfg(feature = "launch-credentials")]
    pub(crate) fn proof_key_sha384(&self) -> &str {
        &self.inner.signer_sha384
    }

    #[cfg(feature = "launch-credentials")]
    pub(crate) fn same_instance(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Rebuild the operation only from this service's immutable completed request,
    /// nonce and aggregate. A historical aggregate alone cannot enter delivery.
    #[cfg(feature = "launch-credentials")]
    pub(crate) fn credential_policy(
        &self,
        session_id: &str,
        aggregate_sha384: &str,
        recorder_public_key: &[u8; 32],
        signature: &str,
    ) -> Result<CompletedCredentialPolicy, ResourceError> {
        if !hash(aggregate_sha384) {
            return Err(ResourceError::InvalidRequest);
        }
        let entries = self.inner.lock()?;
        let entry = entries.get(session_id).ok_or(ResourceError::NotFound)?;
        let RequestStatus::Complete {
            request,
            signed_bytes,
        } = &entry.status
        else {
            return Err(ResourceError::Rejected);
        };
        let signed: Signed<LaunchPolicyAggregateV1> =
            serde_json::from_slice(signed_bytes).map_err(|_| ResourceError::Internal)?;
        let digest = signed
            .statement
            .digest_sha384()
            .map_err(|_| ResourceError::Internal)?;
        if digest != aggregate_sha384 {
            return Err(ResourceError::Conflict);
        }
        let operation = SessionOperation::CredentialDelivery {
            session_id: session_id.to_owned(),
            nonce: entry.challenge.nonce.clone(),
            runtime_sha384: entry.challenge.runtime_sha384.clone(),
            evidence_sha384: entry.challenge.evidence_sha384.clone(),
            request_sha384: request
                .request
                .digest_sha384()
                .map_err(|_| ResourceError::Internal)?,
            aggregate_sha384: digest.clone(),
        };
        let view = self.sessions().live_resource_view(
            session_id,
            &operation,
            recorder_public_key,
            signature,
        )?;
        self.sessions().recheck_live_view(&entry.view)?;
        Ok(CompletedCredentialPolicy {
            owner: self.inner.clone(),
            view: Arc::new(view),
            request: request.request.clone(),
            aggregate: signed_bytes.clone(),
            aggregate_sha384: digest,
        })
    }

    #[cfg(feature = "launch-credentials")]
    pub(crate) fn recheck_credential_policy(
        &self,
        context: &CompletedCredentialPolicy,
    ) -> Result<(), ResourceError> {
        if !Arc::ptr_eq(&self.inner, &context.owner) {
            return Err(ResourceError::Conflict);
        }
        let entries = self.inner.lock()?;
        let entry = entries
            .get(context.view.session_id())
            .ok_or(ResourceError::NotFound)?;
        let RequestStatus::Complete {
            request,
            signed_bytes,
        } = &entry.status
        else {
            return Err(ResourceError::Rejected);
        };
        if request.request != context.request || !Arc::ptr_eq(signed_bytes, &context.aggregate) {
            return Err(ResourceError::Conflict);
        }
        self.sessions().recheck_live_view(&context.view)?;
        Ok(())
    }

    /// A new operation PoP over the quote nonce is required even for a challenge
    /// retry. The resource nonce itself is generated only once for this session.
    pub fn challenge(
        &self,
        session_id: &str,
        recorder_public_key: &[u8; 32],
        signature: &str,
    ) -> Result<ResourceChallenge, ResourceError> {
        let view = self.sessions().live_resource_challenge_view(
            session_id,
            recorder_public_key,
            signature,
        )?;
        let mut entries = self.inner.lock()?;
        if let Some(entry) = entries.get(session_id) {
            if entry.view.grant_sha384() != view.grant_sha384()
                || entry.view.expected().report_data() != view.expected().report_data()
            {
                return Err(ResourceError::Conflict);
            }
            if matches!(entry.status, RequestStatus::Rejected) {
                return Err(ResourceError::Rejected);
            }
            self.sessions().recheck_live_view(&entry.view)?;
            return Ok(entry.challenge.clone());
        }
        if entries.len() >= self.inner.config.capacity {
            return Err(ResourceError::Capacity);
        }
        self.sessions().recheck_live_view(&view)?;
        let mut nonce = [0_u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| ResourceError::Internal)?;
        let challenge = ResourceChallenge {
            session_id: session_id.to_owned(),
            nonce: hex::encode(nonce),
            grant_sha384: view.grant_sha384().to_owned(),
            runtime_sha384: hex::encode(view.expected().report_data()),
            evidence_sha384: view.appraisal().evidence().evidence_sha384().to_owned(),
            init_data_sha384: hex::encode(view.expected().init_data()),
            recorder_key_sha384: view.binding().channel_key_sha384.clone(),
        };
        entries.insert(
            session_id.to_owned(),
            ResourceEntry {
                view: Arc::new(view),
                challenge: challenge.clone(),
                revision: 0,
                status: RequestStatus::Ready,
            },
        );
        Ok(challenge)
    }

    /// Evaluate only server-derived request data and verified AS claims.
    /// No public facts object or caller JSON can substitute the captured session.
    pub async fn decide(
        &self,
        session_id: &str,
        request: &ResourcePolicyRequest,
        recorder_public_key: &[u8; 32],
        signature: &str,
    ) -> Result<ResourceOutcome, ResourceError> {
        let mut started = match self.claim(session_id, request, recorder_public_key, signature)? {
            DecisionClaim::Started(started) => started,
            DecisionClaim::Outcome(outcome) => return Ok(outcome),
        };
        let data = policy_data(&started.request.request)?;
        let input = policy_input(&started.view)?;
        let facts = evaluate_kbs_policy(
            &self.inner.config.engine,
            &self.inner.config.policy_id,
            &data,
            &input,
        )
        .await
        .map_err(|_| ResourceError::PolicyDenied)?;
        let capture = facts.capture();
        if capture.policy_commitment().sha384() != self.inner.config.policy_sha384
            || capture.actual_policy_id() != self.inner.config.policy_id
            || capture.input_bytes() != input.as_bytes()
            || capture.data_bytes() != Some(data.as_bytes())
        {
            return Err(ResourceError::PolicyMismatch);
        }
        let aggregate = self.aggregate(&started.view, &started.request.request, capture)?;
        // The final live check, signing, and publication share the state lock.
        // No completed or failed request can be evaluated for a second time.
        let mut entries = self.inner.lock()?;
        let entry = entries.get_mut(session_id).ok_or(ResourceError::NotFound)?;
        if entry.revision != started.guard.revision {
            return Err(ResourceError::Conflict);
        }
        let RequestStatus::Evaluating(bound) = &entry.status else {
            return Err(ResourceError::Conflict);
        };
        if !Arc::ptr_eq(bound, &started.request) {
            return Err(ResourceError::Conflict);
        }
        self.sessions().recheck_live_view(&started.view)?;
        let bytes = aggregate
            .signing_bytes()
            .map_err(|_| ResourceError::Internal)?;
        let wire = serde_json::to_vec(&Signed {
            statement: aggregate,
            signature: hex::encode(self.inner.config.signer.sign(&bytes).as_ref()),
        })
        .map_err(|_| ResourceError::Internal)?;
        if wire.len() > MAX_WIRE_BYTES {
            return Err(ResourceError::Internal);
        }
        let signed_bytes: Arc<[u8]> = Arc::from(wire);
        entry.status = RequestStatus::Complete {
            request: started.request.clone(),
            signed_bytes: signed_bytes.clone(),
        };
        started.guard.active = false;
        Ok(ResourceOutcome::Current(signed_bytes))
    }

    fn claim(
        &self,
        session_id: &str,
        request: &ResourcePolicyRequest,
        recorder_public_key: &[u8; 32],
        signature: &str,
    ) -> Result<DecisionClaim, ResourceError> {
        let request_sha384 = request
            .digest_sha384()
            .map_err(|_| ResourceError::InvalidRequest)?;
        if request
            .resource_path
            .iter()
            .any(|part| !resource_part(part))
        {
            return Err(ResourceError::InvalidRequest);
        }
        if signature.len() != 128 {
            return Err(ResourceError::InvalidPossession);
        }
        let mut entries = self.inner.lock()?;
        let entry = entries.get_mut(session_id).ok_or(ResourceError::NotFound)?;
        if request.request_nonce != entry.challenge.nonce {
            return Err(ResourceError::Conflict);
        }
        let operation = SessionOperation::ResourceDecision {
            session_id: session_id.to_owned(),
            nonce: entry.challenge.nonce.clone(),
            runtime_sha384: entry.challenge.runtime_sha384.clone(),
            evidence_sha384: entry.challenge.evidence_sha384.clone(),
            request_sha384: request_sha384.clone(),
        };
        self.sessions().authenticate_resource_retry(
            &entry.view,
            &operation,
            recorder_public_key,
            signature,
        )?;
        match &entry.status {
            RequestStatus::Evaluating(bound) => {
                return if bound.matches(request, recorder_public_key, signature) {
                    Ok(DecisionClaim::Outcome(ResourceOutcome::Pending))
                } else {
                    Err(ResourceError::Conflict)
                }
            }
            RequestStatus::Complete {
                request: bound,
                signed_bytes,
            } => {
                return if bound.matches(request, recorder_public_key, signature) {
                    Ok(DecisionClaim::Outcome(ResourceOutcome::Historical(
                        signed_bytes.clone(),
                    )))
                } else {
                    Err(ResourceError::Conflict)
                }
            }
            RequestStatus::Rejected => return Err(ResourceError::Rejected),
            RequestStatus::Ready => {}
        }
        self.sessions().recheck_live_view(&entry.view)?;
        if self.inner.signer_sha384 == entry.view.authority_key_sha384()
            || self.inner.signer_sha384 == entry.view.binding().channel_key_sha384
        {
            return Err(ResourceError::InvalidConfig);
        }
        let revision = entry
            .revision
            .checked_add(1)
            .ok_or(ResourceError::Internal)?;
        let request = Arc::new(SubmittedRequest {
            request: request.clone(),
            recorder_public_key: *recorder_public_key,
            signature: signature.to_owned(),
        });
        entry.revision = revision;
        entry.status = RequestStatus::Evaluating(request.clone());
        Ok(DecisionClaim::Started(Box::new(StartedDecision {
            guard: DecisionGuard {
                inner: self.inner.clone(),
                session_id: session_id.to_owned(),
                revision,
                active: true,
            },
            view: entry.view.clone(),
            request,
        })))
    }

    fn aggregate(
        &self,
        view: &LiveLaunchView,
        request: &ResourcePolicyRequest,
        kbs: &CapturedEvaluation,
    ) -> Result<LaunchPolicyAggregateV1, ResourceError> {
        Ok(LaunchPolicyAggregateV1 {
            version: POLICY_AGGREGATE_VERSION,
            purpose: POLICY_AGGREGATE_PURPOSE.into(),
            audience: self.inner.config.audience.clone(),
            issuer: self.inner.config.issuer.clone(),
            profile: self.inner.config.profile.clone(),
            grant_sha384: view.grant_sha384().into(),
            authority_key_sha384: view.authority_key_sha384().into(),
            session_id: view.session_id().into(),
            nonce: view.expected().nonce().into(),
            runtime_sha384: hex::encode(view.expected().report_data()),
            init_data_sha384: hex::encode(view.expected().init_data()),
            evidence_sha384: view.appraisal().evidence().evidence_sha384().into(),
            recorder_key_sha384: view.binding().channel_key_sha384.clone(),
            request: request.clone(),
            as_evaluation: commitments(view.appraisal().policy().capture()),
            kbs_evaluation: commitments(kbs),
        })
    }
}

impl Inner {
    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, ResourceEntry>>, ResourceError> {
        self.entries.lock().map_err(|_| ResourceError::Internal)
    }
}

enum DecisionClaim {
    Started(Box<StartedDecision>),
    Outcome(ResourceOutcome),
}
struct StartedDecision {
    guard: DecisionGuard,
    view: Arc<LiveLaunchView>,
    request: Arc<SubmittedRequest>,
}
struct DecisionGuard {
    inner: Arc<Inner>,
    session_id: String,
    revision: u64,
    active: bool,
}
impl Drop for DecisionGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut entries) = self.inner.entries.lock() {
            if let Some(entry) = entries.get_mut(&self.session_id) {
                if entry.revision == self.revision
                    && matches!(entry.status, RequestStatus::Evaluating(_))
                {
                    entry.status = RequestStatus::Rejected;
                }
            }
        }
    }
}

fn commitments(capture: &CapturedEvaluation) -> PolicyCommitments {
    PolicyCommitments {
        policy_id: capture.actual_policy_id().into(),
        policy_sha384: capture.policy_commitment().sha384().into(),
        input_sha384: capture.input_commitment().sha384().into(),
        data_sha384: capture.data_commitment().map(|data| data.sha384().into()),
    }
}
fn policy_data(request: &ResourcePolicyRequest) -> Result<String, ResourceError> {
    serde_json::to_string(&json!({"method":request.method,"plugin":request.plugin,"resource-path":request.resource_path,
        "workflow-id":request.workflow_id,"request_nonce":request.request_nonce,"query":{}})).map_err(|_|ResourceError::Internal)
}
fn policy_input(view: &LiveLaunchView) -> Result<String, ResourceError> {
    serde_json::to_string(&json!({"profile":RESOURCE_INPUT_PROFILE,"verified_launch":{
        "grant_sha384":view.grant_sha384(),"authority_key_sha384":view.authority_key_sha384(),"binding":view.binding(),
        "session_id":view.session_id(),"nonce":view.expected().nonce(),"runtime_sha384":hex::encode(view.expected().report_data()),
        "init_data_sha384":hex::encode(view.expected().init_data()),"evidence_sha384":view.appraisal().evidence().evidence_sha384(),
        "claims":view.appraisal().evidence().claims()}})).map_err(|_|ResourceError::Internal)
}
fn hash_hex(bytes: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA384, bytes))
}
fn hash(value: &str) -> bool {
    value.len() == 96
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn policy_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn resource_part(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        && bytes.all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
