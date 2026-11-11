// SPDX-License-Identifier: Apache-2.0

//! Opt-in publication of an encrypted credential for one completed policy
//! decision. Each operation authenticates recorder possession and rechecks
//! live session time even for cached responses. Policy history alone cannot
//! release a credential. State is bounded and process-local, not durable replay
//! or clone protection; publication does not prove recipient receipt or use.
//! Clones share one state machine; independent service instances do not share
//! delivery state and must not be treated as one replay domain.

use crate::{
    gcp_launch_resource::{CompletedCredentialPolicy, LaunchResourceService, ResourceError},
    gcp_launch_session::MAX_SESSIONS,
    plugins::resource::{ResourceDesc, ResourceStorage},
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use execution_proof_contract::{
    gcp_credential::{
        GcpCredentialDeliveryV2, CREDENTIAL_DELIVERY_PROFILE, CREDENTIAL_DELIVERY_PURPOSE,
        CREDENTIAL_DELIVERY_VERSION, MAX_CREDENTIAL_BYTES, MAX_CREDENTIAL_JWE_BYTES,
    },
    Signed, MAX_WIRE_BYTES,
};
use kbs_types::TeePubKey;
use ring::{
    digest,
    signature::{Ed25519KeyPair, KeyPair},
};
use rsa::{BigUint, RsaPublicKey};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};
use zeroize::Zeroize;

/// Constructor-only dependencies and allowed credential scope. The resource
/// backend uses the KBS implementation and cannot be selected by a request.
pub struct LaunchCredentialConfig {
    pub resource: LaunchResourceService,
    pub storage: ResourceStorage,
    pub resource_path: [String; 3],
    pub workflow_id: String,
    pub signer: Ed25519KeyPair,
    pub audience: String,
    pub issuer: String,
    pub capacity: usize,
}

/// Ciphertext and signed metadata only. No public constructor or raw Debug.
pub struct CredentialBundle {
    signed_delivery: Vec<u8>,
    jwe: Vec<u8>,
}
impl CredentialBundle {
    pub fn signed_delivery_json(&self) -> &[u8] {
        &self.signed_delivery
    }
    pub fn jwe_json(&self) -> &[u8] {
        &self.jwe
    }
}

/// Existing ciphertext is returned only after the same live checks as Current.
/// There is intentionally no clock-free Historical credential response.
pub enum CredentialOutcome {
    Pending,
    Current(Arc<CredentialBundle>),
    Existing(Arc<CredentialBundle>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialError {
    InvalidConfig,
    InvalidRequest,
    UnsupportedKey,
    Resource(ResourceError),
    ScopeMismatch,
    Capacity,
    Conflict,
    Rejected,
    TooLarge,
    BackendUnavailable,
    EncryptionFailed,
    Internal,
}
impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "credential delivery configuration rejected",
            Self::InvalidRequest => "credential delivery request rejected",
            Self::UnsupportedKey => "credential delivery requires a supported RSA-OAEP-256 key",
            Self::Resource(_) => "credential delivery session check failed",
            Self::ScopeMismatch => "credential delivery scope rejected",
            Self::Capacity => "credential delivery capacity exhausted",
            Self::Conflict => "credential delivery transcript conflict",
            Self::Rejected => "credential delivery rejected",
            Self::TooLarge => "credential delivery exceeds bounds",
            Self::BackendUnavailable => "credential backend unavailable",
            Self::EncryptionFailed => "credential encryption failed",
            Self::Internal => "credential delivery state unavailable",
        })
    }
}
impl std::error::Error for CredentialError {}
impl From<ResourceError> for CredentialError {
    fn from(error: ResourceError) -> Self {
        Self::Resource(error)
    }
}

struct Submission {
    aggregate_sha384: String,
    public_key: [u8; 32],
    signature: String,
}
impl Submission {
    fn matches(&self, aggregate: &str, key: &[u8; 32], signature: &str) -> bool {
        self.aggregate_sha384 == aggregate && self.public_key == *key && self.signature == signature
    }
}
enum Status {
    Publishing(Arc<Submission>),
    Complete {
        submission: Arc<Submission>,
        bundle: Arc<CredentialBundle>,
    },
    Rejected,
}
struct Entry {
    status: Status,
}
struct Inner {
    config: LaunchCredentialConfig,
    entries: Mutex<HashMap<String, Entry>>,
}
#[derive(Clone)]
pub struct LaunchCredentialService {
    inner: Arc<Inner>,
}

impl LaunchCredentialService {
    pub fn new(config: LaunchCredentialConfig) -> Result<Self, CredentialError> {
        if !(1..=MAX_SESSIONS).contains(&config.capacity)
            || config.resource_path.iter().any(|part| !resource_part(part))
            || !identifier(&config.workflow_id)
            || !identifier(&config.audience)
            || !identifier(&config.issuer)
            || hash(config.signer.public_key().as_ref()) != config.resource.proof_key_sha384()
        {
            return Err(CredentialError::InvalidConfig);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                entries: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub(crate) fn uses_resource(&self, resource: &LaunchResourceService) -> bool {
        self.inner.config.resource.same_instance(resource)
    }

    pub async fn deliver(
        &self,
        session_id: &str,
        aggregate_sha384: &str,
        public_key: &[u8; 32],
        signature: &str,
    ) -> Result<CredentialOutcome, CredentialError> {
        if !lower_hex(session_id, 32)
            || !lower_hex(aggregate_sha384, 48)
            || !lower_hex(signature, 64)
        {
            return Err(CredentialError::InvalidRequest);
        }
        // Authenticate this purpose against the owning L,
        // request and nonce. It requires a completed policy and live clock.
        let context = self.inner.config.resource.credential_policy(
            session_id,
            aggregate_sha384,
            public_key,
            signature,
        )?;
        if context.request().resource_path != self.inner.config.resource_path
            || context.request().workflow_id != self.inner.config.workflow_id
        {
            return Err(CredentialError::ScopeMismatch);
        }
        let started = match self.claim(context, public_key, signature)? {
            Claim::Started(started) => started,
            Claim::Outcome(outcome) => return Ok(outcome),
        };
        let (key, keywrap_sha384) = recipient(&started.context)?;
        let path = &self.inner.config.resource_path;
        let mut plaintext = self
            .inner
            .config
            .storage
            .get_secret_resource(ResourceDesc {
                repository_name: path[0].clone(),
                resource_type: path[1].clone(),
                resource_tag: path[2].clone(),
            })
            .await
            .map_err(|_| CredentialError::BackendUnavailable)?;
        if plaintext.is_empty() || plaintext.len() > MAX_CREDENTIAL_BYTES {
            plaintext.zeroize();
            return Err(CredentialError::TooLarge);
        }
        if let Err(error) = self
            .inner
            .config
            .resource
            .recheck_credential_policy(&started.context)
        {
            plaintext.zeroize();
            return Err(error.into());
        }
        // KBS crypto encrypts the owned payload in place. No
        // plaintext, plaintext hash or credential parser result enters a receipt.
        let jwe = crate::jwe::jwe(key, plaintext).map_err(|_| CredentialError::EncryptionFailed)?;
        let jwe = serde_json::to_vec(&jwe).map_err(|_| CredentialError::EncryptionFailed)?;
        if jwe.len() > MAX_CREDENTIAL_JWE_BYTES {
            return Err(CredentialError::TooLarge);
        }
        self.publish(*started, keywrap_sha384, jwe)
    }

    fn claim(
        &self,
        context: CompletedCredentialPolicy,
        key: &[u8; 32],
        signature: &str,
    ) -> Result<Claim, CredentialError> {
        let mut entries = self.inner.lock()?;
        // Queueing for this lock must not allow a cached/new response to cross
        // the window without another trusted sample.
        self.inner
            .config
            .resource
            .recheck_credential_policy(&context)?;
        let id = context.view().session_id();
        if let Some(entry) = entries.get(id) {
            return match &entry.status {
                Status::Publishing(submission)
                    if submission.matches(context.aggregate_sha384(), key, signature) =>
                {
                    Ok(Claim::Outcome(CredentialOutcome::Pending))
                }
                Status::Complete { submission, bundle }
                    if submission.matches(context.aggregate_sha384(), key, signature) =>
                {
                    Ok(Claim::Outcome(CredentialOutcome::Existing(bundle.clone())))
                }
                Status::Publishing(_) | Status::Complete { .. } => Err(CredentialError::Conflict),
                Status::Rejected => Err(CredentialError::Rejected),
            };
        }
        if entries.len() >= self.inner.config.capacity {
            return Err(CredentialError::Capacity);
        }
        let id = id.to_owned();
        let submission = Arc::new(Submission {
            aggregate_sha384: context.aggregate_sha384().to_owned(),
            public_key: *key,
            signature: signature.to_owned(),
        });
        entries.insert(
            id.clone(),
            Entry {
                status: Status::Publishing(submission.clone()),
            },
        );
        Ok(Claim::Started(Box::new(Started {
            guard: Guard {
                inner: self.inner.clone(),
                session_id: id,
                submission: submission.clone(),
                active: true,
            },
            context,
            submission,
        })))
    }

    fn publish(
        &self,
        mut started: Started,
        keywrap_sha384: String,
        jwe: Vec<u8>,
    ) -> Result<CredentialOutcome, CredentialError> {
        let context = &started.context;
        let view = context.view();
        let receipt = GcpCredentialDeliveryV2 {
            version: CREDENTIAL_DELIVERY_VERSION,
            purpose: CREDENTIAL_DELIVERY_PURPOSE.into(),
            audience: self.inner.config.audience.clone(),
            issuer: self.inner.config.issuer.clone(),
            profile: CREDENTIAL_DELIVERY_PROFILE.into(),
            grant_sha384: view.grant_sha384().into(),
            aggregate_sha384: context.aggregate_sha384().into(),
            request_sha384: context
                .request()
                .digest_sha384()
                .map_err(|_| CredentialError::Internal)?,
            session_id: view.session_id().into(),
            runtime_sha384: hash(view.expected().canonical_runtime()),
            evidence_sha384: view.appraisal().evidence().evidence_sha384().into(),
            boot_binding_sha384: view.expected().boot_binding_sha384().to_owned(),
            recorder_key_sha384: view.binding().channel_key_sha384.clone(),
            keywrap_sha384,
            ciphertext_sha384: hash(&jwe),
            workflow_id: self.inner.config.workflow_id.clone(),
            resource_path: self.inner.config.resource_path.clone(),
            validity: *view.validity(),
        };
        let mut entries = self.inner.lock()?;
        let entry = entries
            .get_mut(view.session_id())
            .ok_or(CredentialError::Internal)?;
        let Status::Publishing(bound) = &entry.status else {
            return Err(CredentialError::Conflict);
        };
        if !Arc::ptr_eq(bound, &started.submission) {
            return Err(CredentialError::Conflict);
        }
        self.inner
            .config
            .resource
            .recheck_credential_policy(context)?;
        let bytes = receipt
            .signing_bytes()
            .map_err(|_| CredentialError::Internal)?;
        let signed_delivery = serde_json::to_vec(&Signed {
            statement: receipt,
            signature: hex::encode(self.inner.config.signer.sign(&bytes).as_ref()),
        })
        .map_err(|_| CredentialError::Internal)?;
        if signed_delivery.len() > MAX_WIRE_BYTES {
            return Err(CredentialError::TooLarge);
        }
        let bundle = Arc::new(CredentialBundle {
            signed_delivery,
            jwe,
        });
        entry.status = Status::Complete {
            submission: started.submission.clone(),
            bundle: bundle.clone(),
        };
        started.guard.active = false;
        Ok(CredentialOutcome::Current(bundle))
    }
}
impl Inner {
    fn lock(&self) -> Result<MutexGuard<'_, HashMap<String, Entry>>, CredentialError> {
        self.entries.lock().map_err(|_| CredentialError::Internal)
    }
}
enum Claim {
    Started(Box<Started>),
    Outcome(CredentialOutcome),
}
struct Started {
    guard: Guard,
    context: CompletedCredentialPolicy,
    submission: Arc<Submission>,
}
struct Guard {
    inner: Arc<Inner>,
    session_id: String,
    submission: Arc<Submission>,
    active: bool,
}
impl Drop for Guard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut entries) = self.inner.entries.lock() {
            if let Some(entry) = entries.get_mut(&self.session_id) {
                if matches!(&entry.status, Status::Publishing(bound) if Arc::ptr_eq(bound, &self.submission))
                {
                    entry.status = Status::Rejected;
                }
            }
        }
    }
}

fn recipient(context: &CompletedCredentialPolicy) -> Result<(TeePubKey, String), CredentialError> {
    let runtime: serde_json::Value =
        serde_json::from_slice(context.view().expected().canonical_runtime())
            .map_err(|_| CredentialError::Internal)?;
    let key: TeePubKey = serde_json::from_value(
        runtime
            .get("tee-pubkey")
            .cloned()
            .ok_or(CredentialError::Internal)?,
    )
    .map_err(|_| CredentialError::Internal)?;
    let TeePubKey::RSA { alg, k_mod, k_exp } = &key else {
        return Err(CredentialError::UnsupportedKey);
    };
    if alg != "RSA-OAEP-256" {
        return Err(CredentialError::UnsupportedKey);
    }
    let modulus = URL_SAFE_NO_PAD
        .decode(k_mod)
        .map_err(|_| CredentialError::UnsupportedKey)?;
    let exponent = URL_SAFE_NO_PAD
        .decode(k_exp)
        .map_err(|_| CredentialError::UnsupportedKey)?;
    if URL_SAFE_NO_PAD.encode(&modulus) != *k_mod || URL_SAFE_NO_PAD.encode(&exponent) != *k_exp {
        return Err(CredentialError::UnsupportedKey);
    }
    let n = BigUint::from_bytes_be(&modulus);
    if !(2048..=4096).contains(&n.bits()) {
        return Err(CredentialError::UnsupportedKey);
    }
    RsaPublicKey::new(n, BigUint::from_bytes_be(&exponent))
        .map_err(|_| CredentialError::UnsupportedKey)?;
    let canonical =
        serde_json_canonicalizer::to_vec(&key).map_err(|_| CredentialError::Internal)?;
    Ok((key, hash(&canonical)))
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA384, bytes))
}
fn lower_hex(value: &str, bytes: usize) -> bool {
    value.len() == bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
}
fn resource_part(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= 128
        && bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}
