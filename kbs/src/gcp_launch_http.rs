// SPDX-License-Identifier: Apache-2.0

//! Default-off HTTP transport for launch quote and resource-policy transcripts.
//!
//! The embedding server constructs this service from trusted operator inputs.
//! Routes never consult legacy bearer tokens or cookies. A captured transcript
//! and a signed policy aggregate do not grant resource delivery or execution.
//! No raw grant, evidence, claims, policy, or reference-data dump is returned.

#[cfg(feature = "launch-gcp-credentials")]
use crate::gcp_launch_credential::{CredentialError, CredentialOutcome, LaunchCredentialService};
use crate::{
    gcp_launch_resource::{LaunchResourceService, ResourceError, ResourceOutcome},
    gcp_launch_session::{CaptureOutcome, FreshLaunchSessions, SessionBackend, SessionError},
};
use actix_web::{http::StatusCode, web, HttpResponse, ResponseError};
use attestation_service::config::VerifierConfig;
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_contract::MAX_WIRE_BYTES;
use key_value_storage::StorageProvider;
use policy_engine::{rego::Regorus, PolicyEngine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fmt, sync::Arc};

pub const LAUNCH_HTTP_PREFIX: &str = "/kbs/launch/gcp/v2";
pub const MAX_BEGIN_BODY_BYTES: usize = 64 * 1024;
pub const MAX_CAPTURE_BODY_BYTES: usize = 6 * 1024 * 1024;
pub const MAX_OPERATION_BODY_BYTES: usize = 16 * 1024;
const MAX_EVIDENCE_BYTES: usize = 4 * 1024 * 1024;

/// Owned AS inputs. Public callers cannot substitute a verification callback.
pub struct LaunchHttpBackend {
    pub verifier_config: Option<VerifierConfig>,
    pub storage: Arc<dyn StorageProvider>,
    pub engine: PolicyEngine<Regorus>,
}

/// Share one instance through `web::Data` across every HTTP worker. `sessions`
/// and the resource service must refer to clones of the same session instance.
pub struct LaunchHttpService {
    sessions: FreshLaunchSessions,
    backend: LaunchHttpBackend,
    resource: LaunchResourceService,
    #[cfg(feature = "launch-gcp-credentials")]
    credential: Option<LaunchCredentialService>,
}

impl LaunchHttpService {
    pub fn new(
        sessions: FreshLaunchSessions,
        backend: LaunchHttpBackend,
        resource: LaunchResourceService,
    ) -> Result<Self, SessionError> {
        if !sessions.same_instance(resource.sessions()) {
            return Err(SessionError::InvalidConfig);
        }
        Ok(Self {
            sessions,
            backend,
            resource,
            #[cfg(feature = "launch-gcp-credentials")]
            credential: None,
        })
    }

    #[cfg(feature = "launch-gcp-credentials")]
    pub fn with_credential_service(
        mut self,
        service: LaunchCredentialService,
    ) -> Result<Self, CredentialError> {
        if !service.uses_resource(&self.resource) {
            return Err(CredentialError::InvalidConfig);
        }
        self.credential = Some(service);
        Ok(self)
    }
}

use execution_proof_client::gcp::{
    check_wire_domain, BEGIN_PURPOSE, CAPTURE_PURPOSE, CREDENTIAL_PURPOSE,
    RESOURCE_CHALLENGE_PURPOSE, RESOURCE_DECISION_PURPOSE, WIRE_VERSION,
};
pub use execution_proof_client::gcp::{
    GcpBeginRequestV2 as BeginRequest, GcpBeginResponseV2 as BeginResponse,
    GcpCaptureRequestV2 as CaptureRequest, GcpCredentialRequestV2 as CredentialDeliveryRequest,
    GcpCredentialResponseV2 as CredentialDeliveryResponse,
    GcpResourceChallengeRequestV2 as ResourceChallengeRequest,
    GcpResourceChallengeResponseV2 as ResourceChallengeResponse,
    GcpResourceDecisionRequestV2 as ResourceDecisionRequest,
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum CaptureState {
    Pending,
    Captured,
    Historical,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureCommitments {
    pub grant_digest: String,
    pub evidence_sha384: String,
    pub policy_sha384: String,
    pub input_sha384: String,
    pub reference_data_sha384: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureResponse {
    pub version: u16,
    pub purpose: String,
    pub boot_binding_sha384: String,
    pub outcome: CaptureState,
    pub commitments: Option<CaptureCommitments>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ResourceDecisionState {
    Pending,
    Current,
    Historical,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDecisionResponse {
    pub version: u16,
    pub purpose: String,
    pub boot_binding_sha384: String,
    pub outcome: ResourceDecisionState,
    pub signed_aggregate_b64: Option<String>,
    pub historical: bool,
}

/// Register only when the embedding server explicitly enables this service.
/// Extractor limits apply before the handlers' bounded JSON parsing, including
/// chunked bodies. Handler checks retain the bounds for direct/internal calls.
pub fn configure(cfg: &mut web::ServiceConfig) {
    #[cfg(feature = "launch-gcp-credentials")]
    let credential = |scope: &mut web::ServiceConfig| {
        scope.service(
            web::resource("/credential-delivery")
                .app_data(web::PayloadConfig::new(MAX_OPERATION_BODY_BYTES))
                .route(web::post().to(credential_delivery)),
        );
    };
    #[cfg(not(feature = "launch-gcp-credentials"))]
    let credential = |_scope: &mut web::ServiceConfig| {};
    cfg.service(
        web::scope(LAUNCH_HTTP_PREFIX)
            .configure(credential)
            .app_data(web::PayloadConfig::new(MAX_CAPTURE_BODY_BYTES))
            .service(
                web::resource("/begin")
                    .app_data(web::PayloadConfig::new(MAX_BEGIN_BODY_BYTES))
                    .route(web::post().to(begin)),
            )
            .service(
                web::resource("/capture")
                    .app_data(web::PayloadConfig::new(MAX_CAPTURE_BODY_BYTES))
                    .route(web::post().to(capture)),
            )
            .service(
                web::resource("/resource-challenge")
                    .app_data(web::PayloadConfig::new(MAX_OPERATION_BODY_BYTES))
                    .route(web::post().to(resource_challenge)),
            )
            .service(
                web::resource("/resource-decision")
                    .app_data(web::PayloadConfig::new(MAX_OPERATION_BODY_BYTES))
                    .route(web::post().to(resource_decision)),
            ),
    );
}

#[derive(Clone, Copy, Debug)]
enum HttpError {
    InvalidRequest,
    TooLarge,
    Denied,
    NotFound,
    Conflict,
    Unavailable,
}

impl HttpError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::TooLarge => "too_large",
            Self::Denied => "denied",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Unavailable => "service_unavailable",
        }
    }
}
impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl ResponseError for HttpError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Denied => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(serde_json::json!({"error": self.code()}))
    }
}

impl From<SessionError> for HttpError {
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::TooLarge => Self::TooLarge,
            SessionError::NotFound => Self::NotFound,
            SessionError::Conflict => Self::Conflict,
            SessionError::InvalidConfig
            | SessionError::Capacity
            | SessionError::ClockUnavailable
            | SessionError::ClockOutOfRange
            | SessionError::ClockRegression
            | SessionError::StateUnavailable => Self::Unavailable,
            SessionError::InvalidGrant
            | SessionError::InvalidKey
            | SessionError::Expired
            | SessionError::NotYetValid
            | SessionError::InvalidPossession
            | SessionError::Rejected
            | SessionError::VerificationFailed => Self::Denied,
        }
    }
}
impl From<ResourceError> for HttpError {
    fn from(error: ResourceError) -> Self {
        match error {
            ResourceError::Session(error) => error.into(),
            ResourceError::InvalidRequest => Self::InvalidRequest,
            ResourceError::NotFound => Self::NotFound,
            ResourceError::Conflict => Self::Conflict,
            ResourceError::InvalidPossession
            | ResourceError::Rejected
            | ResourceError::PolicyDenied
            | ResourceError::PolicyMismatch => Self::Denied,
            ResourceError::InvalidConfig | ResourceError::Capacity | ResourceError::Internal => {
                Self::Unavailable
            }
        }
    }
}

#[cfg(feature = "launch-gcp-credentials")]
impl From<CredentialError> for HttpError {
    fn from(error: CredentialError) -> Self {
        match error {
            CredentialError::Resource(error) => error.into(),
            CredentialError::InvalidRequest | CredentialError::UnsupportedKey => {
                Self::InvalidRequest
            }
            CredentialError::ScopeMismatch | CredentialError::Rejected => Self::Denied,
            CredentialError::Conflict => Self::Conflict,
            CredentialError::TooLarge => Self::TooLarge,
            CredentialError::InvalidConfig
            | CredentialError::Capacity
            | CredentialError::BackendUnavailable
            | CredentialError::EncryptionFailed
            | CredentialError::Internal => Self::Unavailable,
        }
    }
}

fn parse<T: DeserializeOwned>(body: &[u8], bound: usize) -> Result<T, HttpError> {
    if body.len() > bound {
        return Err(HttpError::TooLarge);
    }
    serde_json::from_slice(body).map_err(|_| HttpError::InvalidRequest)
}

fn decode(encoded: &str, bound: usize) -> Result<Vec<u8>, HttpError> {
    let encoded_bound = bound.div_ceil(3) * 4;
    if encoded.len() > encoded_bound {
        return Err(HttpError::TooLarge);
    }
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|_| HttpError::InvalidRequest)?;
    if bytes.len() > bound {
        return Err(HttpError::TooLarge);
    }
    if bytes.is_empty() || STANDARD.encode(&bytes) != encoded {
        return Err(HttpError::InvalidRequest);
    }
    Ok(bytes)
}

fn hex_field(encoded: &str, byte_len: usize) -> Result<(), HttpError> {
    if encoded.len() != byte_len * 2
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(HttpError::InvalidRequest);
    }
    Ok(())
}

fn possession(key: &str, signature: &str) -> Result<[u8; 32], HttpError> {
    hex_field(key, 32)?;
    hex_field(signature, 64)?;
    let mut bytes = [0; 32];
    hex::decode_to_slice(key, &mut bytes).map_err(|_| HttpError::InvalidRequest)?;
    Ok(bytes)
}

#[cfg(feature = "launch-gcp-credentials")]
async fn credential_delivery(
    body: web::Bytes,
    service: web::Data<LaunchHttpService>,
) -> Result<HttpResponse, HttpError> {
    let credential = service.credential.as_ref().ok_or(HttpError::Unavailable)?;
    let request: CredentialDeliveryRequest = parse(&body, MAX_OPERATION_BODY_BYTES)?;
    check_wire_domain(
        request.version,
        &request.purpose,
        &request.boot_binding_sha384,
        CREDENTIAL_PURPOSE,
        &service.sessions.boot_binding_sha384(),
    )
    .map_err(|_| HttpError::InvalidRequest)?;
    hex_field(&request.session_id, 32)?;
    hex_field(&request.aggregate_sha384, 48)?;
    let key = possession(&request.recorder_public_key_hex, &request.signature_hex)?;
    let bundle = match credential
        .deliver(
            &request.session_id,
            &request.aggregate_sha384,
            &key,
            &request.signature_hex,
        )
        .await?
    {
        CredentialOutcome::Pending => {
            return Ok(HttpResponse::Accepted().json(serde_json::json!({"version":WIRE_VERSION,"purpose":CREDENTIAL_PURPOSE,"boot_binding_sha384":service.sessions.boot_binding_sha384(),"outcome":"pending"})))
        }
        CredentialOutcome::Current(bundle) | CredentialOutcome::Existing(bundle) => bundle,
    };
    Ok(HttpResponse::Ok().json(CredentialDeliveryResponse {
        version: WIRE_VERSION,
        purpose: CREDENTIAL_PURPOSE.into(),
        boot_binding_sha384: service.sessions.boot_binding_sha384(),
        signed_delivery_b64: STANDARD.encode(bundle.signed_delivery_json()),
        jwe_b64: STANDARD.encode(bundle.jwe_json()),
    }))
}

async fn begin(
    body: web::Bytes,
    service: web::Data<LaunchHttpService>,
) -> Result<HttpResponse, HttpError> {
    let request: BeginRequest = parse(&body, MAX_BEGIN_BODY_BYTES)?;
    check_wire_domain(
        request.version,
        &request.purpose,
        &request.boot_binding_sha384,
        BEGIN_PURPOSE,
        &service.sessions.boot_binding_sha384(),
    )
    .map_err(|_| HttpError::InvalidRequest)?;
    let key = possession(&request.recorder_public_key_hex, &request.signature_hex)?;
    let grant = decode(&request.signed_grant_b64, MAX_WIRE_BYTES)?;
    let challenge = service.sessions.begin_authenticated(
        &grant,
        &request.keywrap_public_key,
        &key,
        &request.signature_hex,
    )?;
    let expected = challenge.expected_quote();
    Ok(HttpResponse::Ok().json(BeginResponse {
        version: WIRE_VERSION,
        purpose: BEGIN_PURPOSE.into(),
        boot_binding_sha384: service.sessions.boot_binding_sha384(),
        session_id: challenge.session_id().into(),
        quote_nonce: expected.nonce().into(),
        grant_digest: expected.grant_digest().into(),
        canonical_runtime_b64: STANDARD.encode(expected.canonical_runtime()),
        server_nonce_hex: challenge.server_nonce_hex(),
    }))
}

async fn capture(
    body: web::Bytes,
    service: web::Data<LaunchHttpService>,
) -> Result<HttpResponse, HttpError> {
    let request: CaptureRequest = parse(&body, MAX_CAPTURE_BODY_BYTES)?;
    check_wire_domain(
        request.version,
        &request.purpose,
        &request.boot_binding_sha384,
        CAPTURE_PURPOSE,
        &service.sessions.boot_binding_sha384(),
    )
    .map_err(|_| HttpError::InvalidRequest)?;
    hex_field(&request.session_id, 32)?;
    let key = possession(&request.recorder_public_key_hex, &request.signature_hex)?;
    let evidence = decode(&request.evidence_b64, MAX_EVIDENCE_BYTES)?;
    let outcome = service
        .sessions
        .capture(
            &request.session_id,
            &evidence,
            &key,
            &request.signature_hex,
            SessionBackend {
                verifier_config: service.backend.verifier_config.clone(),
                storage: service.backend.storage.clone(),
                engine: &service.backend.engine,
            },
        )
        .await?;
    let (outcome, appraisal) = match outcome {
        CaptureOutcome::Pending => (CaptureState::Pending, None),
        CaptureOutcome::Captured(appraisal) => (CaptureState::Captured, Some(appraisal)),
        CaptureOutcome::Historical(appraisal) => (CaptureState::Historical, Some(appraisal)),
    };
    let commitments = appraisal.map(|appraisal| {
        let evidence = appraisal.evidence();
        let capture = appraisal.policy().capture();
        CaptureCommitments {
            grant_digest: evidence.expected().grant_digest().into(),
            evidence_sha384: evidence.evidence_sha384().into(),
            policy_sha384: capture.policy_commitment().sha384().into(),
            input_sha384: capture.input_commitment().sha384().into(),
            reference_data_sha384: capture.data_commitment().map(|value| value.sha384().into()),
        }
    });
    let status = if outcome == CaptureState::Pending {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok(HttpResponse::build(status).json(CaptureResponse {
        version: WIRE_VERSION,
        purpose: CAPTURE_PURPOSE.into(),
        boot_binding_sha384: service.sessions.boot_binding_sha384(),
        outcome,
        commitments,
    }))
}

async fn resource_challenge(
    body: web::Bytes,
    service: web::Data<LaunchHttpService>,
) -> Result<HttpResponse, HttpError> {
    let request: ResourceChallengeRequest = parse(&body, MAX_OPERATION_BODY_BYTES)?;
    check_wire_domain(
        request.version,
        &request.purpose,
        &request.boot_binding_sha384,
        RESOURCE_CHALLENGE_PURPOSE,
        &service.sessions.boot_binding_sha384(),
    )
    .map_err(|_| HttpError::InvalidRequest)?;
    hex_field(&request.session_id, 32)?;
    let key = possession(&request.recorder_public_key_hex, &request.signature_hex)?;
    let challenge =
        service
            .resource
            .challenge(&request.session_id, &key, &request.signature_hex)?;
    Ok(HttpResponse::Ok().json(ResourceChallengeResponse {
        version: WIRE_VERSION,
        purpose: RESOURCE_CHALLENGE_PURPOSE.into(),
        boot_binding_sha384: service.sessions.boot_binding_sha384(),
        session_id: challenge.session_id().into(),
        request_nonce: challenge.nonce().into(),
        grant_sha384: challenge.grant_sha384().into(),
        runtime_sha384: challenge.runtime_sha384().into(),
        evidence_sha384: challenge.evidence_sha384().into(),
        recorder_key_sha384: challenge.recorder_key_sha384().into(),
    }))
}

async fn resource_decision(
    body: web::Bytes,
    service: web::Data<LaunchHttpService>,
) -> Result<HttpResponse, HttpError> {
    let request: ResourceDecisionRequest = parse(&body, MAX_OPERATION_BODY_BYTES)?;
    check_wire_domain(
        request.version,
        &request.purpose,
        &request.boot_binding_sha384,
        RESOURCE_DECISION_PURPOSE,
        &service.sessions.boot_binding_sha384(),
    )
    .map_err(|_| HttpError::InvalidRequest)?;
    hex_field(&request.session_id, 32)?;
    let key = possession(&request.recorder_public_key_hex, &request.signature_hex)?;
    let outcome = service
        .resource
        .decide(
            &request.session_id,
            &request.request,
            &key,
            &request.signature_hex,
        )
        .await?;
    let (outcome, bytes, historical) = match outcome {
        ResourceOutcome::Pending => (ResourceDecisionState::Pending, None, false),
        ResourceOutcome::Current(bytes) => (ResourceDecisionState::Current, Some(bytes), false),
        ResourceOutcome::Historical(bytes) => {
            (ResourceDecisionState::Historical, Some(bytes), true)
        }
    };
    let status = if outcome == ResourceDecisionState::Pending {
        StatusCode::ACCEPTED
    } else {
        StatusCode::OK
    };
    Ok(HttpResponse::build(status).json(ResourceDecisionResponse {
        version: WIRE_VERSION,
        purpose: RESOURCE_DECISION_PURPOSE.into(),
        boot_binding_sha384: service.sessions.boot_binding_sha384(),
        outcome,
        signed_aggregate_b64: bytes.map(|bytes| STANDARD.encode(bytes.as_ref())),
        historical,
    }))
}
