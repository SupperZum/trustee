// SPDX-License-Identifier: Apache-2.0

//! Default-off HTTP transport for launch quote and resource-policy transcripts.
//!
//! The embedding server constructs this service from trusted operator inputs.
//! Routes never consult legacy bearer tokens or cookies. A captured transcript
//! and a signed policy aggregate do not grant resource delivery or execution.
//! No raw grant, evidence, claims, policy, or reference-data dump is returned.

#[cfg(feature = "launch-credentials")]
use crate::launch_credential::{CredentialError, CredentialOutcome, LaunchCredentialService};
use crate::{
    launch_resource::{LaunchResourceService, ResourceError, ResourceOutcome},
    launch_session::{CaptureOutcome, FreshLaunchSessions, SessionBackend, SessionError},
};
use actix_web::{http::StatusCode, web, HttpResponse, ResponseError};
use attestation_service::config::VerifierConfig;
use base64::{engine::general_purpose::STANDARD, Engine};
use execution_proof_contract::{policy_receipt::ResourcePolicyRequest, MAX_WIRE_BYTES};
use kbs_types::TeePubKey;
use key_value_storage::StorageProvider;
use policy_engine::{rego::Regorus, PolicyEngine};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fmt, sync::Arc};

pub const LAUNCH_HTTP_PREFIX: &str = "/kbs/launch/v1";
pub const MAX_BEGIN_BODY_BYTES: usize = 64 * 1024;
pub const MAX_CAPTURE_BODY_BYTES: usize = 1536 * 1024;
pub const MAX_OPERATION_BODY_BYTES: usize = 16 * 1024;
const MAX_EVIDENCE_BYTES: usize = 1024 * 1024;

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
    #[cfg(feature = "launch-credentials")]
    credential: Option<LaunchCredentialService>,
}

impl LaunchHttpService {
    pub fn new(
        sessions: FreshLaunchSessions,
        backend: LaunchHttpBackend,
        resource: LaunchResourceService,
    ) -> Self {
        Self {
            sessions,
            backend,
            resource,
            #[cfg(feature = "launch-credentials")]
            credential: None,
        }
    }

    #[cfg(feature = "launch-credentials")]
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

#[cfg(feature = "launch-credentials")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDeliveryRequest {
    pub session_id: String,
    pub aggregate_sha384: String,
    pub recorder_public_key_hex: String,
    pub signature_hex: String,
}

#[cfg(feature = "launch-credentials")]
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDeliveryResponse {
    pub signed_delivery_b64: String,
    pub jwe_b64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginRequest {
    pub signed_grant_b64: String,
    pub keywrap_public_key: TeePubKey,
    pub recorder_public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    pub session_id: String,
    pub evidence_b64: String,
    pub recorder_public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceChallengeRequest {
    pub session_id: String,
    pub recorder_public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDecisionRequest {
    pub session_id: String,
    pub request: ResourcePolicyRequest,
    pub recorder_public_key_hex: String,
    pub signature_hex: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginResponse {
    pub session_id: String,
    pub quote_nonce: String,
    pub grant_digest: String,
    pub canonical_runtime_b64: String,
    pub init_data_sha384: String,
}

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
    pub outcome: CaptureState,
    pub commitments: Option<CaptureCommitments>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceChallengeResponse {
    pub session_id: String,
    pub request_nonce: String,
    pub grant_sha384: String,
    pub runtime_sha384: String,
    pub evidence_sha384: String,
    pub init_data_sha384: String,
    pub recorder_key_sha384: String,
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
    pub outcome: ResourceDecisionState,
    pub signed_aggregate_b64: Option<String>,
    pub historical: bool,
}

/// Register only when the embedding server explicitly enables this service.
/// Extractor limits apply before the handlers' bounded JSON parsing, including
/// chunked bodies. Handler checks retain the bounds for direct/internal calls.
pub fn configure(cfg: &mut web::ServiceConfig) {
    #[cfg(feature = "launch-credentials")]
    let credential = |scope: &mut web::ServiceConfig| {
        scope.service(
            web::resource("/credential-delivery")
                .app_data(web::PayloadConfig::new(MAX_OPERATION_BODY_BYTES))
                .route(web::post().to(credential_delivery)),
        );
    };
    #[cfg(not(feature = "launch-credentials"))]
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

#[cfg(feature = "launch-credentials")]
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

#[cfg(feature = "launch-credentials")]
async fn credential_delivery(
    body: web::Bytes,
    service: web::Data<LaunchHttpService>,
) -> Result<HttpResponse, HttpError> {
    let credential = service.credential.as_ref().ok_or(HttpError::Unavailable)?;
    let request: CredentialDeliveryRequest = parse(&body, MAX_OPERATION_BODY_BYTES)?;
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
            return Ok(HttpResponse::Accepted().json(serde_json::json!({"outcome":"pending"})))
        }
        CredentialOutcome::Current(bundle) | CredentialOutcome::Existing(bundle) => bundle,
    };
    Ok(HttpResponse::Ok().json(CredentialDeliveryResponse {
        signed_delivery_b64: STANDARD.encode(bundle.signed_delivery_json()),
        jwe_b64: STANDARD.encode(bundle.jwe_json()),
    }))
}

async fn begin(
    body: web::Bytes,
    service: web::Data<LaunchHttpService>,
) -> Result<HttpResponse, HttpError> {
    let request: BeginRequest = parse(&body, MAX_BEGIN_BODY_BYTES)?;
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
        session_id: challenge.session_id().into(),
        quote_nonce: expected.nonce().into(),
        grant_digest: expected.grant_digest().into(),
        canonical_runtime_b64: STANDARD.encode(expected.canonical_runtime()),
        init_data_sha384: hex::encode(expected.init_data()),
    }))
}

async fn capture(
    body: web::Bytes,
    service: web::Data<LaunchHttpService>,
) -> Result<HttpResponse, HttpError> {
    let request: CaptureRequest = parse(&body, MAX_CAPTURE_BODY_BYTES)?;
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
        outcome,
        commitments,
    }))
}

async fn resource_challenge(
    body: web::Bytes,
    service: web::Data<LaunchHttpService>,
) -> Result<HttpResponse, HttpError> {
    let request: ResourceChallengeRequest = parse(&body, MAX_OPERATION_BODY_BYTES)?;
    hex_field(&request.session_id, 32)?;
    let key = possession(&request.recorder_public_key_hex, &request.signature_hex)?;
    let challenge =
        service
            .resource
            .challenge(&request.session_id, &key, &request.signature_hex)?;
    Ok(HttpResponse::Ok().json(ResourceChallengeResponse {
        session_id: challenge.session_id().into(),
        request_nonce: challenge.nonce().into(),
        grant_sha384: challenge.grant_sha384().into(),
        runtime_sha384: challenge.runtime_sha384().into(),
        evidence_sha384: challenge.evidence_sha384().into(),
        init_data_sha384: challenge.init_data_sha384().into(),
        recorder_key_sha384: challenge.recorder_key_sha384().into(),
    }))
}

async fn resource_decision(
    body: web::Bytes,
    service: web::Data<LaunchHttpService>,
) -> Result<HttpResponse, HttpError> {
    let request: ResourceDecisionRequest = parse(&body, MAX_OPERATION_BODY_BYTES)?;
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
        outcome,
        signed_aggregate_b64: bytes.map(|bytes| STANDARD.encode(bytes.as_ref())),
        historical,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        launch_resource::LaunchResourceConfig,
        launch_session::{SessionClock, SessionConfig},
    };
    use actix_web::{test as http_test, App};
    use execution_proof_contract::{
        policy_receipt::POLICY_AGGREGATE_PROFILE,
        session::{operation_signing_bytes, SessionOperation},
        verify_launch_grant, GrantExpectations, LaunchBinding, LaunchGrant, Signed, ValidityWindow,
        GRANT_PURPOSE, VERSION,
    };
    use key_value_storage::{
        memory::MemoryKeyValueStorage, KvStorageProvider, StorageBackendConfig,
    };
    use ring::{
        digest,
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };

    struct Clock;
    impl SessionClock for Clock {
        fn now_unix_seconds(&self) -> Result<u64, SessionError> {
            Ok(10)
        }
    }

    fn key() -> Ed25519KeyPair {
        let encoded = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap()
    }
    fn hash(bytes: &[u8]) -> String {
        hex::encode(digest::digest(&digest::SHA384, bytes))
    }
    fn engine() -> PolicyEngine<Regorus> {
        PolicyEngine::new(Arc::new(MemoryKeyValueStorage::default()))
    }

    fn fixture() -> (web::Data<LaunchHttpService>, BeginRequest) {
        let authority = key();
        let recorder = key();
        let grant = LaunchGrant {
            version: VERSION,
            purpose: GRANT_PURPOSE.into(),
            audience: "http-software-fixture".into(),
            proof_required: true,
            grant_id: "grant".into(),
            validity: ValidityWindow {
                not_before: 10,
                expires: 20,
            },
            binding: LaunchBinding {
                authority: "authority".into(),
                tenant: "tenant".into(),
                workload_id: "workload".into(),
                container_role: "application-init".into(),
                attempt_id: "attempt".into(),
                boot_id: "boot".into(),
                channel_key_sha384: hash(recorder.public_key().as_ref()),
                bootstrap_context_sha384: "11".repeat(48),
                selected_manifest_sha256: "12".repeat(32),
                effective_launch_sha384: "13".repeat(48),
                profile_sha384: "14".repeat(48),
                launch_policy_sha384: "15".repeat(48),
                image_policy_sha384: "16".repeat(48),
                challenge_sha384: "17".repeat(48),
            },
        };
        let expected = GrantExpectations {
            authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
            audience: grant.audience.clone(),
            authority: grant.binding.authority.clone(),
            tenant: grant.binding.tenant.clone(),
            profile_sha384: grant.binding.profile_sha384.clone(),
            launch_policy_sha384: grant.binding.launch_policy_sha384.clone(),
            image_policy_sha384: grant.binding.image_policy_sha384.clone(),
        };
        let signature = hex::encode(authority.sign(&grant.signing_bytes().unwrap()).as_ref());
        let wire = serde_json::to_vec(&Signed {
            statement: grant,
            signature,
        })
        .unwrap();
        let verified = verify_launch_grant(&wire, &expected, 10).unwrap();
        let wrapping_key = TeePubKey::RSA {
            alg: "RSA-OAEP-256".into(),
            k_mod: "AQID".into(),
            k_exp: "AQAB".into(),
        };
        let operation = SessionOperation::Begin {
            key_sha384: hash(&serde_json_canonicalizer::to_vec(&wrapping_key).unwrap()),
        };
        let signature_hex = hex::encode(
            recorder
                .sign(&operation_signing_bytes(&verified, &operation).unwrap())
                .as_ref(),
        );
        let request = BeginRequest {
            signed_grant_b64: STANDARD.encode(wire),
            keywrap_public_key: wrapping_key,
            recorder_public_key_hex: hex::encode(recorder.public_key().as_ref()),
            signature_hex,
        };
        let sessions = FreshLaunchSessions::new(
            SessionConfig {
                grant_expectations: expected,
                expected_init_data_sha384: [8; 48],
                selected_policy_id: "launch_cpu".into(),
                reference_data: None,
                capacity: 8,
            },
            Arc::new(Clock),
        )
        .unwrap();
        let resource = LaunchResourceService::new(LaunchResourceConfig {
            sessions: sessions.clone(),
            engine: engine(),
            policy_id: "launch_resource".into(),
            policy_sha384: "18".repeat(48),
            signer: key(),
            audience: "http-software-fixture".into(),
            issuer: "kbs-proof-fixture".into(),
            profile: POLICY_AGGREGATE_PROFILE.into(),
            capacity: 8,
        })
        .unwrap();
        let backend = LaunchHttpBackend {
            verifier_config: None,
            storage: KvStorageProvider::new(StorageBackendConfig::default()),
            engine: engine(),
        };
        (
            web::Data::new(LaunchHttpService::new(sessions, backend, resource)),
            request,
        )
    }

    #[actix_web::test]
    async fn routes_are_absent_without_explicit_configuration() {
        let app = http_test::init_service(App::new()).await;
        for endpoint in [
            "begin",
            "capture",
            "resource-challenge",
            "resource-decision",
        ] {
            let request = http_test::TestRequest::post()
                .uri(&format!("{LAUNCH_HTTP_PREFIX}/{endpoint}"))
                .set_payload("{}")
                .to_request();
            assert_eq!(
                http_test::call_service(&app, request).await.status(),
                StatusCode::NOT_FOUND
            );
        }
    }

    #[actix_web::test]
    async fn malformed_unknown_and_duplicate_json_fields_do_not_echo_payloads() {
        let (state, _) = fixture();
        let app = http_test::init_service(App::new().app_data(state).configure(configure)).await;
        for payload in [
            "{confidential-http-marker",
            "{\"confidential-http-marker\":true}",
            "{\"session_id\":\"one\",\"session_id\":\"two\"}",
        ] {
            let request = http_test::TestRequest::post()
                .uri(&format!("{LAUNCH_HTTP_PREFIX}/capture"))
                .set_payload(payload)
                .to_request();
            let response = http_test::call_service(&app, request).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert!(
                !String::from_utf8_lossy(&http_test::read_body(response).await)
                    .contains("confidential-http-marker")
            );
        }
        for suffix in ["status", "abort", "evidence"] {
            let request = http_test::TestRequest::post()
                .uri(&format!("{LAUNCH_HTTP_PREFIX}/{suffix}"))
                .to_request();
            assert_eq!(
                http_test::call_service(&app, request).await.status(),
                StatusCode::NOT_FOUND
            );
        }
    }

    #[actix_web::test]
    async fn per_route_payload_overflow_is_rejected_before_invalid_json() {
        let (state, _) = fixture();
        let app = http_test::init_service(App::new().app_data(state).configure(configure)).await;
        for (endpoint, bound) in [
            ("begin", MAX_BEGIN_BODY_BYTES),
            ("capture", MAX_CAPTURE_BODY_BYTES),
            ("resource-challenge", MAX_OPERATION_BODY_BYTES),
            ("resource-decision", MAX_OPERATION_BODY_BYTES),
        ] {
            let request = http_test::TestRequest::post()
                .uri(&format!("{LAUNCH_HTTP_PREFIX}/{endpoint}"))
                .set_payload(vec![b'{'; bound + 1])
                .to_request();
            assert_eq!(
                http_test::call_service(&app, request).await.status(),
                StatusCode::PAYLOAD_TOO_LARGE
            );
        }
    }

    #[test]
    fn canonical_base64_and_hex_are_bounded_before_decode() {
        assert_eq!(decode("BQ==", 1).unwrap(), vec![5]);
        for invalid in ["BQ", "BR==", "BQ==\n", "", "____"] {
            assert!(decode(invalid, 16).is_err());
        }
        assert!(matches!(decode("QUFBQUFB", 1), Err(HttpError::TooLarge)));
        assert!(matches!(
            hex_field(&"AA".repeat(32), 32),
            Err(HttpError::InvalidRequest)
        ));
        assert!(matches!(
            hex_field(&"00".repeat(31), 32),
            Err(HttpError::InvalidRequest)
        ));
    }

    #[actix_web::test]
    async fn genuine_begin_pop_shares_one_challenge_across_app_instances() {
        let (state, request) = fixture();
        let first_app =
            http_test::init_service(App::new().app_data(state.clone()).configure(configure)).await;
        let second_app =
            http_test::init_service(App::new().app_data(state).configure(configure)).await;
        let payload = serde_json::to_vec(&request).unwrap();
        let first = http_test::call_service(
            &first_app,
            http_test::TestRequest::post()
                .uri(&format!("{LAUNCH_HTTP_PREFIX}/begin"))
                .set_payload(payload.clone())
                .to_request(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);
        let first: BeginResponse = http_test::read_body_json(first).await;
        let second = http_test::call_service(
            &second_app,
            http_test::TestRequest::post()
                .uri(&format!("{LAUNCH_HTTP_PREFIX}/begin"))
                .set_payload(payload)
                .to_request(),
        )
        .await;
        assert_eq!(second.status(), StatusCode::OK);
        let second: BeginResponse = http_test::read_body_json(second).await;
        assert_eq!(first.session_id, second.session_id);
        assert_eq!(first.quote_nonce, second.quote_nonce);
        assert_eq!(first.canonical_runtime_b64, second.canonical_runtime_b64);
        let mut changed = request;
        if let TeePubKey::RSA { k_mod, .. } = &mut changed.keywrap_public_key {
            *k_mod = "BAUG".into();
        }
        let response = http_test::call_service(
            &second_app,
            http_test::TestRequest::post()
                .uri(&format!("{LAUNCH_HTTP_PREFIX}/begin"))
                .set_payload(serde_json::to_vec(&changed).unwrap())
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn bearer_and_cookie_cannot_replace_missing_or_forged_recorder_pop() {
        let (state, mut request) = fixture();
        let app = http_test::init_service(App::new().app_data(state).configure(configure)).await;
        let mut no_pop = serde_json::to_value(&request).unwrap();
        no_pop.as_object_mut().unwrap().remove("signature_hex");
        let response = http_test::call_service(
            &app,
            http_test::TestRequest::post()
                .uri(&format!("{LAUNCH_HTTP_PREFIX}/begin"))
                .insert_header(("Authorization", "Bearer confidential-http-marker"))
                .insert_header(("Cookie", "kbs-session-id=confidential-http-marker"))
                .set_payload(serde_json::to_vec(&no_pop).unwrap())
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            !String::from_utf8_lossy(&http_test::read_body(response).await)
                .contains("confidential-http-marker")
        );
        request.signature_hex = "00".repeat(64);
        let response = http_test::call_service(
            &app,
            http_test::TestRequest::post()
                .uri(&format!("{LAUNCH_HTTP_PREFIX}/begin"))
                .insert_header(("Authorization", "Bearer old-token"))
                .insert_header(("Cookie", "kbs-session-id=old-session"))
                .set_payload(serde_json::to_vec(&request).unwrap())
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
}
