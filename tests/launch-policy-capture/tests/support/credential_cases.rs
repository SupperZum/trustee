//! Software AS fixtures followed by policy, resource, JWE, and signature paths.
//! These tests provide no hardware, Cloud KMS, or network evidence.

use super::*;
use actix_web::{http::StatusCode, test as http_test, web, App};
use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use execution_proof_contract::{
    credential::{verify_credential_delivery, DeliveryExpectations, MAX_CREDENTIAL_BYTES},
    policy_receipt::{
        verify_policy_aggregate, AggregateExpectations, LaunchPolicyAggregateV1,
        ResourcePolicyRequest,
    },
    session::{operation_signing_bytes, recorder_session_signing_bytes, SessionOperation},
    verify_launch_grant, GrantExpectations, Signed,
};
use key_value_storage::{
    memory::MemoryKeyValueStorage, KeyValueStorage, KeyValueStorageInstance, KeyValueStorageType,
    SetParameters, SetResult, StorageProvider,
};
use launch_credential::{
    CredentialBundle, CredentialError, CredentialOutcome, LaunchCredentialConfig,
    LaunchCredentialService,
};
use openssl::{
    encrypt::Decrypter,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
    symm::{decrypt_aead, Cipher},
};
use ring::signature::Ed25519KeyPair;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use test_support::{hash, Fixture};

const SECRET: &[u8] = b"synthetic-credential-never-log-this";
const PATH: [&str; 3] = ["tenant-1", "image-key", "v1"];

struct Backend {
    inner: MemoryKeyValueStorage,
    reads: AtomicUsize,
    gate: Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>,
}
impl Backend {
    fn new(gated: bool) -> Arc<Self> {
        Arc::new(Self {
            inner: MemoryKeyValueStorage::default(),
            reads: AtomicUsize::new(0),
            gate: gated.then(|| {
                (
                    Arc::new(tokio::sync::Notify::new()),
                    Arc::new(tokio::sync::Notify::new()),
                )
            }),
        })
    }
    async fn put(&self, bytes: &[u8]) {
        self.inner
            .set(&PATH.join("/"), bytes, SetParameters { overwrite: true })
            .await
            .unwrap();
    }
}
#[async_trait]
impl KeyValueStorage for Backend {
    async fn set(
        &self,
        key: &str,
        value: &[u8],
        parameters: SetParameters,
    ) -> key_value_storage::Result<SetResult> {
        self.inner.set(key, value, parameters).await
    }
    async fn list(&self) -> key_value_storage::Result<Vec<String>> {
        self.inner.list().await
    }
    async fn get(&self, key: &str) -> key_value_storage::Result<Option<Vec<u8>>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        if let Some((entered, release)) = &self.gate {
            entered.notify_one();
            release.notified().await;
        }
        self.inner.get(key).await
    }
    async fn delete(&self, key: &str) -> key_value_storage::Result<Option<Vec<u8>>> {
        self.inner.delete(key).await
    }
}
struct Provider(Arc<Backend>);
#[async_trait]
impl StorageProvider for Provider {
    async fn get_or_register(
        &self,
        namespace: &str,
    ) -> key_value_storage::Result<KeyValueStorageInstance> {
        assert_eq!(
            namespace,
            credential_resource_backend::RESOURCE_STORAGE_NAMESPACE
        );
        Ok(self.0.clone())
    }
    async fn get_or_register_with_type(
        &self,
        namespace: &str,
        _kind: KeyValueStorageType,
    ) -> key_value_storage::Result<KeyValueStorageInstance> {
        self.get_or_register(namespace).await
    }
}

struct Completed {
    session: launch_session::FreshChallenge,
    evidence: Vec<u8>,
    challenge: launch_resource::ResourceChallenge,
    request: ResourcePolicyRequest,
    aggregate: Vec<u8>,
}
impl Completed {
    fn digest(&self) -> String {
        let signed: Signed<LaunchPolicyAggregateV1> =
            serde_json::from_slice(&self.aggregate).unwrap();
        signed.statement.digest_sha384().unwrap()
    }
    fn signature(&self, f: &Fixture) -> String {
        f.operation_signature(&SessionOperation::CredentialDelivery {
            session_id: self.session.session_id().into(),
            nonce: self.challenge.nonce().into(),
            runtime_sha384: self.challenge.runtime_sha384().into(),
            evidence_sha384: self.challenge.evidence_sha384().into(),
            request_sha384: self.request.digest_sha384().unwrap(),
            aggregate_sha384: self.digest(),
        })
    }
}
async fn completed(f: &Fixture) -> Completed {
    let (session, evidence) = f.capture_software().await;
    let challenge = f.resource_challenge(&session, &evidence);
    let request = f.request(&challenge);
    let aggregate = match f
        .resource
        .decide(
            session.session_id(),
            &request,
            &f.recorder_public,
            &f.decision_signature(&challenge, &request),
        )
        .await
        .unwrap()
    {
        launch_resource::ResourceOutcome::Current(bytes) => bytes.to_vec(),
        _ => panic!("first policy result must be current"),
    };
    Completed {
        session,
        evidence,
        challenge,
        request,
        aggregate,
    }
}
fn recipient() -> (PKey<Private>, kbs_types::TeePubKey) {
    let rsa = Rsa::generate(2048).unwrap();
    let public = kbs_types::TeePubKey::RSA {
        alg: "RSA-OAEP-256".into(),
        k_mod: URL_SAFE_NO_PAD.encode(rsa.n().to_vec()),
        k_exp: URL_SAFE_NO_PAD.encode(rsa.e().to_vec()),
    };
    (PKey::from_rsa(rsa).unwrap(), public)
}
async fn fixture() -> (Fixture, PKey<Private>, Completed) {
    let (private, public) = recipient();
    let f = Fixture::with_resource_storage_and_keywrap(
        Arc::new(MemoryKeyValueStorage::default()),
        public,
    )
    .await;
    let done = completed(&f).await;
    (f, private, done)
}
async fn config(f: &Fixture, backend: Arc<Backend>, capacity: usize) -> LaunchCredentialConfig {
    let storage = ResourceStorage::new(
        credential_resource_backend::RepositoryConfig::KvStorage,
        Arc::new(Provider(backend)),
    )
    .await
    .unwrap();
    LaunchCredentialConfig {
        resource: f.resource.clone(),
        storage,
        resource_path: PATH.map(str::to_owned),
        workflow_id: "image-decrypt-policy".into(),
        signer: Ed25519KeyPair::from_pkcs8(&f.proof_pkcs8).unwrap(),
        audience: "credential-client".into(),
        issuer: "kbs-proof-fixture".into(),
        capacity,
    }
}
async fn service(f: &Fixture, backend: Arc<Backend>) -> LaunchCredentialService {
    LaunchCredentialService::new(config(f, backend, 8).await).unwrap()
}
async fn deliver(
    service: &LaunchCredentialService,
    f: &Fixture,
    done: &Completed,
) -> Result<CredentialOutcome, CredentialError> {
    service
        .deliver(
            done.session.session_id(),
            &done.digest(),
            &f.recorder_public,
            &done.signature(f),
        )
        .await
}
fn current(outcome: CredentialOutcome) -> Arc<CredentialBundle> {
    match outcome {
        CredentialOutcome::Current(value) => value,
        _ => panic!("first delivery must be current"),
    }
}
fn decrypt(private: &PKey<Private>, bundle: &CredentialBundle) -> Vec<u8> {
    let response: kbs_types::Response = serde_json::from_slice(bundle.jwe_json()).unwrap();
    let mut rsa = Decrypter::new(private).unwrap();
    rsa.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    rsa.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
    rsa.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
    let mut cek = vec![0; rsa.decrypt_len(&response.encrypted_key).unwrap()];
    let len = rsa.decrypt(&response.encrypted_key, &mut cek).unwrap();
    cek.truncate(len);
    decrypt_aead(
        Cipher::aes_256_gcm(),
        &cek,
        Some(&response.iv),
        &response.protected.generate_aad().unwrap(),
        &response.ciphertext,
        &response.tag,
    )
    .unwrap()
}

#[tokio::test]
async fn actual_resource_jwe_signature_decryption_and_live_exact_retry() {
    let (f, private, done) = fixture().await;
    let backend = Backend::new(false);
    backend.put(SECRET).await;
    let service = service(&f, backend.clone()).await;
    let bundle = current(deliver(&service, &f, &done).await.unwrap());
    let expected =
        bridge_tests::expected_aggregate(&f, &done.session, &done.evidence, &done.request);
    let roots = || AggregateExpectations {
        kbs_proof_public_key: f.proof_public,
        expected: expected.clone(),
    };
    let aggregate = verify_policy_aggregate(&done.aggregate, &f.grant, &roots()).unwrap();
    let verified = verify_credential_delivery(
        bundle.signed_delivery_json(),
        &f.grant,
        &aggregate,
        &DeliveryExpectations {
            aggregate: roots(),
            audience: "credential-client".into(),
            issuer: "kbs-proof-fixture".into(),
            keywrap_sha384: hash(&serde_json_canonicalizer::to_vec(&f.keywrap).unwrap()),
        },
        bundle.jwe_json(),
        1000,
    )
    .unwrap();
    assert_eq!(verified.ciphertext_sha384(), hash(bundle.jwe_json()));
    assert_eq!(decrypt(&private, &bundle), SECRET);
    let receipt = String::from_utf8_lossy(bundle.signed_delivery_json());
    assert!(!receipt.contains(std::str::from_utf8(SECRET).unwrap()));
    assert!(
        !receipt.contains(&hash(SECRET)),
        "plaintext digest must never be published"
    );
    backend.put(b"changed-resource-must-not-be-refetched").await;
    let CredentialOutcome::Existing(retry) = deliver(&service, &f, &done).await.unwrap() else {
        panic!("expected cached live retry");
    };
    assert_eq!(retry.jwe_json(), bundle.jwe_json());
    assert_eq!(retry.signed_delivery_json(), bundle.signed_delivery_json());
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
    f.clock
        .set(Err(launch_session::SessionError::ClockUnavailable));
    assert!(matches!(
        deliver(&service, &f, &done).await,
        Err(CredentialError::Resource(
            launch_resource::ResourceError::Session(launch_session::SessionError::ClockUnavailable)
        ))
    ));
    f.clock.set(Ok(1030));
    assert!(matches!(
        deliver(&service, &f, &done).await,
        Err(CredentialError::Resource(
            launch_resource::ResourceError::Session(launch_session::SessionError::Expired)
        ))
    ));
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn wrong_operation_or_aggregate_cannot_claim_before_rightful_delivery() {
    let (f, _, done) = fixture().await;
    let backend = Backend::new(false);
    backend.put(SECRET).await;
    let service = service(&f, backend.clone()).await;
    let old_signature = f.decision_signature(&done.challenge, &done.request);
    assert!(service
        .deliver(
            done.session.session_id(),
            &done.digest(),
            &f.recorder_public,
            &old_signature
        )
        .await
        .is_err());
    assert!(service
        .deliver(
            done.session.session_id(),
            &"ee".repeat(48),
            &f.recorder_public,
            &done.signature(&f)
        )
        .await
        .is_err());
    let foreign = test_support::key();
    use ring::signature::KeyPair;
    let foreign_public = foreign.public_key().as_ref().try_into().unwrap();
    assert!(service
        .deliver(
            done.session.session_id(),
            &done.digest(),
            &foreign_public,
            &done.signature(&f)
        )
        .await
        .is_err());
    assert_eq!(backend.reads.load(Ordering::SeqCst), 0);
    current(deliver(&service, &f, &done).await.unwrap());
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn scope_key_config_and_backend_errors_fail_closed_and_do_not_rearm() {
    let (f, _, done) = fixture().await;
    let backend = Backend::new(false);
    let mut wrong = config(&f, backend.clone(), 8).await;
    wrong.signer = test_support::key();
    assert!(matches!(
        LaunchCredentialService::new(wrong),
        Err(CredentialError::InvalidConfig)
    ));
    for capacity in [0, launch_session::MAX_SESSIONS + 1] {
        assert!(matches!(
            LaunchCredentialService::new(config(&f, backend.clone(), capacity).await),
            Err(CredentialError::InvalidConfig)
        ));
    }
    let mut wrong = config(&f, backend.clone(), 8).await;
    wrong.resource_path[0] = "other-tenant".into();
    let wrong = LaunchCredentialService::new(wrong).unwrap();
    assert!(matches!(
        deliver(&wrong, &f, &done).await,
        Err(CredentialError::ScopeMismatch)
    ));
    assert_eq!(backend.reads.load(Ordering::SeqCst), 0);
    let missing = service(&f, backend.clone()).await;
    assert!(matches!(
        deliver(&missing, &f, &done).await,
        Err(CredentialError::BackendUnavailable)
    ));
    backend.put(SECRET).await;
    assert!(matches!(
        deliver(&missing, &f, &done).await,
        Err(CredentialError::Rejected)
    ));
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
    let oversized = Backend::new(false);
    oversized.put(&vec![0xab; MAX_CREDENTIAL_BYTES + 1]).await;
    let oversized_service = service(&f, oversized.clone()).await;
    assert!(matches!(
        deliver(&oversized_service, &f, &done).await,
        Err(CredentialError::TooLarge)
    ));
    oversized.put(SECRET).await;
    assert!(matches!(
        deliver(&oversized_service, &f, &done).await,
        Err(CredentialError::Rejected)
    ));
}

#[tokio::test]
async fn unsupported_recipient_never_reads_the_secret() {
    let f = Fixture::new().await; // Deliberately non-cryptographic legacy wire-shape fixture.
    let done = completed(&f).await;
    let backend = Backend::new(false);
    backend.put(SECRET).await;
    let service = service(&f, backend.clone()).await;
    assert!(matches!(
        deliver(&service, &f, &done).await,
        Err(CredentialError::UnsupportedKey)
    ));
    assert_eq!(backend.reads.load(Ordering::SeqCst), 0);
    assert!(matches!(
        deliver(&service, &f, &done).await,
        Err(CredentialError::Rejected)
    ));
}

#[tokio::test]
async fn pending_cancel_and_expiry_during_actual_backend_await_are_fail_closed() {
    let (f, _, done) = fixture().await;
    for cancel in [false, true] {
        let backend = Backend::new(true);
        backend.put(SECRET).await;
        let service = service(&f, backend.clone()).await;
        let worker = service.clone();
        let id = done.session.session_id().to_owned();
        let aggregate = done.digest();
        let public = f.recorder_public;
        let signature = done.signature(&f);
        let task =
            tokio::spawn(async move { worker.deliver(&id, &aggregate, &public, &signature).await });
        let (entered, release) = backend.gate.as_ref().unwrap();
        entered.notified().await;
        assert!(matches!(
            deliver(&service, &f, &done).await.unwrap(),
            CredentialOutcome::Pending
        ));
        if cancel {
            task.abort();
            assert!(task.await.err().expect("cancelled task").is_cancelled());
            assert!(matches!(
                deliver(&service, &f, &done).await,
                Err(CredentialError::Rejected)
            ));
        } else {
            release.notify_one();
            current(task.await.unwrap().unwrap());
        }
        assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
    }
    let backend = Backend::new(true);
    backend.put(SECRET).await;
    let service = service(&f, backend.clone()).await;
    let worker = service.clone();
    let id = done.session.session_id().to_owned();
    let aggregate = done.digest();
    let public = f.recorder_public;
    let signature = done.signature(&f);
    let task =
        tokio::spawn(async move { worker.deliver(&id, &aggregate, &public, &signature).await });
    let (entered, release) = backend.gate.as_ref().unwrap();
    entered.notified().await;
    f.clock.set(Ok(1030));
    release.notify_one();
    assert!(matches!(
        task.await.unwrap(),
        Err(CredentialError::Resource(
            launch_resource::ResourceError::Session(launch_session::SessionError::Expired)
        ))
    ));
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
}

async fn another_completed_request(f: &Fixture) -> (String, String, String) {
    let mut statement = f.grant_statement.clone();
    statement.grant_id = "grant-second".into();
    statement.binding.attempt_id = "attempt-second".into();
    let authority = Ed25519KeyPair::from_pkcs8(&f.authority_pkcs8).unwrap();
    let signature = hex::encode(authority.sign(&statement.signing_bytes().unwrap()).as_ref());
    let expected = GrantExpectations {
        authority_public_key: f.authority_public,
        audience: statement.audience.clone(),
        authority: statement.binding.authority.clone(),
        tenant: statement.binding.tenant.clone(),
        profile_sha384: statement.binding.profile_sha384.clone(),
        launch_policy_sha384: statement.binding.launch_policy_sha384.clone(),
        image_policy_sha384: statement.binding.image_policy_sha384.clone(),
    };
    let wire = serde_json::to_vec(&Signed {
        statement,
        signature,
    })
    .unwrap();
    let grant = verify_launch_grant(&wire, &expected, 1000).unwrap();
    let operation_signature = |operation: &SessionOperation| {
        hex::encode(
            f.recorder
                .sign(&operation_signing_bytes(&grant, operation).unwrap())
                .as_ref(),
        )
    };
    let signature = operation_signature(&SessionOperation::Begin {
        key_sha384: hash(&serde_json_canonicalizer::to_vec(&f.keywrap).unwrap()),
    });
    let session = f
        .sessions
        .begin_authenticated(&wire, &f.keywrap, &f.recorder_public, &signature)
        .unwrap();
    let evidence = launch_evidence::test_support::evidence_bytes(session.expected_quote());
    let appraisal = f.appraise(&session, &evidence).await;
    let signature = hex::encode(
        f.recorder
            .sign(
                &recorder_session_signing_bytes(
                    &grant,
                    session.expected_quote().nonce(),
                    &hex::encode(session.expected_quote().report_data()),
                    &hash(&evidence),
                )
                .unwrap(),
            )
            .as_ref(),
    );
    f.sessions
        .capture_with_test_appraisal(
            session.session_id(),
            &evidence,
            &f.recorder_public,
            &signature,
            appraisal,
        )
        .unwrap();
    let signature = operation_signature(&SessionOperation::ResourceChallenge {
        session_id: session.session_id().into(),
        nonce: session.expected_quote().nonce().into(),
        runtime_sha384: hex::encode(session.expected_quote().report_data()),
        evidence_sha384: hash(&evidence),
    });
    let challenge = f
        .resource
        .challenge(session.session_id(), &f.recorder_public, &signature)
        .unwrap();
    let request = f.request(&challenge);
    let signature = operation_signature(&SessionOperation::ResourceDecision {
        session_id: session.session_id().into(),
        nonce: challenge.nonce().into(),
        runtime_sha384: challenge.runtime_sha384().into(),
        evidence_sha384: challenge.evidence_sha384().into(),
        request_sha384: request.digest_sha384().unwrap(),
    });
    let launch_resource::ResourceOutcome::Current(wire) = f
        .resource
        .decide(
            session.session_id(),
            &request,
            &f.recorder_public,
            &signature,
        )
        .await
        .unwrap()
    else {
        panic!("second attempt requires its own current policy result");
    };
    let signed: Signed<LaunchPolicyAggregateV1> = serde_json::from_slice(&wire).unwrap();
    let digest = signed.statement.digest_sha384().unwrap();
    let signature = operation_signature(&SessionOperation::CredentialDelivery {
        session_id: session.session_id().into(),
        nonce: challenge.nonce().into(),
        runtime_sha384: challenge.runtime_sha384().into(),
        evidence_sha384: challenge.evidence_sha384().into(),
        request_sha384: request.digest_sha384().unwrap(),
        aggregate_sha384: digest.clone(),
    });
    (session.session_id().into(), digest, signature)
}

#[tokio::test]
async fn retained_delivery_slot_exhaustion_does_not_evict_completed_ciphertext() {
    let (f, _, first) = fixture().await;
    let backend = Backend::new(false);
    backend.put(SECRET).await;
    let service = LaunchCredentialService::new(config(&f, backend.clone(), 1).await).unwrap();
    let bundle = current(deliver(&service, &f, &first).await.unwrap());
    let (id, aggregate, signature) = another_completed_request(&f).await;
    assert!(matches!(
        service
            .deliver(&id, &aggregate, &f.recorder_public, &signature)
            .await,
        Err(CredentialError::Capacity)
    ));
    let CredentialOutcome::Existing(retry) = deliver(&service, &f, &first).await.unwrap() else {
        panic!("retained first slot");
    };
    assert_eq!(bundle.jwe_json(), retry.jwe_json());
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
}

#[actix_web::test]
async fn optional_http_delivery_has_no_bearer_fallback_and_returns_only_ciphertext() {
    let (f, private, done) = fixture().await;
    let disabled = http_test::init_service(
        App::new()
            .app_data(f.http_service())
            .configure(launch_http::configure),
    )
    .await;
    let response = http_test::call_service(
        &disabled,
        http_test::TestRequest::post()
            .uri("/kbs/launch/v1/credential-delivery")
            .set_payload("{}")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let backend = Backend::new(false);
    backend.put(SECRET).await;
    let credential = service(&f, backend.clone()).await;
    let state = launch_http::LaunchHttpService::new(
        f.sessions.clone(),
        launch_http::LaunchHttpBackend {
            verifier_config: None,
            storage: f.provider.clone(),
            engine: f.as_engine.clone(),
        },
        f.resource.clone(),
    )
    .with_credential_service(credential)
    .unwrap();
    let app = http_test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .configure(launch_http::configure),
    )
    .await;
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::post()
            .uri("/kbs/launch/v1/credential-delivery")
            .insert_header((
                "Authorization",
                "Bearer synthetic-credential-never-log-this",
            ))
            .insert_header(("Cookie", "kbs-session-id=old"))
            .set_payload("{\"session_id\":\"synthetic-credential-never-log-this\"}")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        !String::from_utf8_lossy(&http_test::read_body(response).await)
            .contains(std::str::from_utf8(SECRET).unwrap())
    );
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::post()
            .uri("/kbs/launch/v1/credential-delivery")
            .set_payload(vec![b'{'; launch_http::MAX_OPERATION_BODY_BYTES + 1])
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(backend.reads.load(Ordering::SeqCst), 0);
    let request = launch_http::CredentialDeliveryRequest {
        session_id: done.session.session_id().into(),
        aggregate_sha384: done.digest(),
        recorder_public_key_hex: hex::encode(f.recorder_public),
        signature_hex: done.signature(&f),
    };
    let body = serde_json::to_vec(&request).unwrap();
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::post()
            .uri("/kbs/launch/v1/credential-delivery")
            .set_payload(body.clone())
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let wire = http_test::read_body(response).await;
    assert!(!String::from_utf8_lossy(&wire).contains(std::str::from_utf8(SECRET).unwrap()));
    let response: launch_http::CredentialDeliveryResponse = serde_json::from_slice(&wire).unwrap();
    let jwe = STANDARD.decode(response.jwe_b64).unwrap();
    let receipt = STANDARD.decode(response.signed_delivery_b64).unwrap();
    let response: kbs_types::Response = serde_json::from_slice(&jwe).unwrap();
    let mut rsa = Decrypter::new(&private).unwrap();
    rsa.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    rsa.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
    rsa.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
    let mut cek = vec![0; rsa.decrypt_len(&response.encrypted_key).unwrap()];
    let len = rsa.decrypt(&response.encrypted_key, &mut cek).unwrap();
    cek.truncate(len);
    assert_eq!(
        decrypt_aead(
            Cipher::aes_256_gcm(),
            &cek,
            Some(&response.iv),
            &response.protected.generate_aad().unwrap(),
            &response.ciphertext,
            &response.tag
        )
        .unwrap(),
        SECRET
    );
    assert!(!receipt.is_empty());
    f.clock.set(Ok(1030));
    let response = http_test::call_service(
        &app,
        http_test::TestRequest::post()
            .uri("/kbs/launch/v1/credential-delivery")
            .set_payload(body)
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(backend.reads.load(Ordering::SeqCst), 1);
}
