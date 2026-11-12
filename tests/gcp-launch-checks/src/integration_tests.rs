use super::*;
#[allow(dead_code)]
mod fixture {
    use super::*;
    use execution_proof_contract::{
        gcp_policy_receipt::POLICY_AGGREGATE_PROFILE,
        gcp_session::{operation_signing_bytes, recorder_session_signing_bytes, SessionOperation},
        policy_receipt::ResourcePolicyRequest,
        verify_launch_grant, GrantExpectations, LaunchBinding, LaunchGrant, Signed, ValidityWindow,
        VerifiedLaunchGrant, GRANT_PURPOSE, VERSION,
    };
    use kbs_types::TeePubKey;
    use key_value_storage::{
        memory::MemoryKeyValueStorage, KeyValueStorage, KvStorageProvider, StorageBackendConfig,
        StorageProvider,
    };
    use policy_engine::{rego::Regorus, PolicyEngine};
    use ring::{
        digest,
        rand::SystemRandom,
        signature::{Ed25519KeyPair, KeyPair},
    };
    use std::sync::{Arc, Mutex};

    pub fn binding() -> execution_proof_contract::gcp_boot_binding::GcpBootBindingV1 {
        execution_proof_contract::gcp_boot_binding::GcpBootBindingV1::new(
            [1; 48], [2; 48], [3; 48], [4; 48],
        )
        .unwrap()
    }
    pub fn boot_policy() -> execution_proof_verifier::gcp_boot_evidence::GcpBootEvidencePolicy {
        use execution_proof_verifier::gcp_boot_evidence::*;
        GcpBootEvidencePolicy{expected_pe_sha384:"c4240c5a835ca1c7b6b9c3dd762477870ba5b7a295ec0f551eb45d442be8926b3d887ea59fa348ff5e8832aaf595c8b4".into(),expected_firmware_mrtd:"f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3".into(),expected_instance:GcpInstanceIdentity{instance_id:1159420029374854386,numerical_project_id:876967775446,zone:"us-central1-a".into()},quote_padding:QuotePaddingPolicy::GcpTsmZeroPadded8000}
    }
    pub fn module_policy() -> execution_proof_verifier::gcp_tdx_policy::GcpTdxModulePolicyV1 {
        use execution_proof_verifier::gcp_tdx_policy::*;
        GcpTdxModulePolicyV1 {
            version: GCP_TDX_POLICY_VERSION,
            purpose: GCP_TDX_POLICY_PURPOSE.into(),
            expected_mr_seam: INTEL_TDX_MODULE_1_5_34_MR_SEAM.into(),
            allowed_td_attributes: GCP_TDX_ALLOWED_ATTRIBUTES,
        }
    }
    pub const AS_POLICY:&str="package policy\nimport rego.v1\nlaunch_accepted if { input.profile == \"onb17.gcp-launch-quote.v2\"; input.runtime_data.nonce != \"\" }\ntrust_claims := {}\nextensions := []\n";
    pub const RESOURCE_POLICY:&str="package policy\nimport rego.v1\ndefault allow := false\nallow if { input.profile == \"onb17.gcp-verified-launch-resource-input.v2\"; input.verified_launch.binding.tenant == \"tenant-1\"; data.method == \"GET\"; data.plugin == \"resource\"; data[\"resource-path\"] == [\"tenant-1\",\"image-key\",\"v1\"]; data[\"workflow-id\"] == \"image-decrypt-policy\" }\n";
    pub fn hash(bytes: &[u8]) -> String {
        hex::encode(digest::digest(&digest::SHA384, bytes))
    }
    pub fn key() -> Ed25519KeyPair {
        let encoded = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(encoded.as_ref()).unwrap()
    }
    pub struct ManualClock(pub Mutex<Result<u64, gcp_launch_session::SessionError>>);
    impl ManualClock {
        pub fn set(&self, value: Result<u64, gcp_launch_session::SessionError>) {
            *self.0.lock().unwrap() = value;
        }
    }
    impl gcp_launch_session::SessionClock for ManualClock {
        fn now_unix_seconds(&self) -> Result<u64, gcp_launch_session::SessionError> {
            *self.0.lock().unwrap()
        }
    }
    pub struct Fixture {
        pub sessions: gcp_launch_session::FreshLaunchSessions,
        pub resource: gcp_launch_resource::LaunchResourceService,
        pub clock: Arc<ManualClock>,
        pub recorder: Ed25519KeyPair,
        // Generated in memory for this fixture; never serialized or written.
        pub recorder_pkcs8: Vec<u8>,
        pub authority_public: [u8; 32],
        #[cfg(feature = "launch-gcp-credentials")]
        pub authority_pkcs8: Vec<u8>,
        pub recorder_public: [u8; 32],
        pub proof_public: [u8; 32],
        #[cfg(feature = "launch-gcp-credentials")]
        pub proof_pkcs8: Vec<u8>,
        pub grant: VerifiedLaunchGrant,
        pub grant_statement: LaunchGrant,
        pub grant_wire: Vec<u8>,
        pub keywrap: TeePubKey,
        pub as_engine: PolicyEngine<Regorus>,
        pub resource_engine: PolicyEngine<Regorus>,
        pub provider: Arc<dyn StorageProvider>,
    }
    impl Fixture {
        pub async fn new() -> Self {
            Self::with_resource_storage(Arc::new(MemoryKeyValueStorage::default())).await
        }
        pub async fn with_resource_storage(storage: Arc<dyn KeyValueStorage>) -> Self {
            Self::with_resource_storage_and_keywrap(
                storage,
                TeePubKey::RSA {
                    alg: "RSA-OAEP-256".into(),
                    k_mod: "AQID".into(),
                    k_exp: "AQAB".into(),
                },
            )
            .await
        }
        pub async fn with_resource_storage_and_keywrap(
            storage: Arc<dyn KeyValueStorage>,
            keywrap: TeePubKey,
        ) -> Self {
            let authority_pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let authority_pkcs8 = authority_pkcs8.as_ref().to_vec();
            let authority = Ed25519KeyPair::from_pkcs8(&authority_pkcs8).unwrap();
            let recorder_pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let recorder_pkcs8 = recorder_pkcs8.as_ref().to_vec();
            let recorder = Ed25519KeyPair::from_pkcs8(&recorder_pkcs8).unwrap();
            let proof_pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
            let proof_pkcs8 = proof_pkcs8.as_ref().to_vec();
            let proof = Ed25519KeyPair::from_pkcs8(&proof_pkcs8).unwrap();
            let recorder_public: [u8; 32] = recorder.public_key().as_ref().try_into().unwrap();
            let proof_public: [u8; 32] = proof.public_key().as_ref().try_into().unwrap();
            let authority_public: [u8; 32] = authority.public_key().as_ref().try_into().unwrap();
            let grant_statement = LaunchGrant {
                version: VERSION,
                purpose: GRANT_PURPOSE.into(),
                audience: "launch-http-software-fixture".into(),
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
                    channel_key_sha384: hash(&recorder_public),
                    bootstrap_context_sha384: "11".repeat(48),
                    selected_manifest_sha256: "12".repeat(32),
                    effective_launch_sha384: "13".repeat(48),
                    profile_sha384: binding().digest_sha384().unwrap(),
                    launch_policy_sha384: hash(AS_POLICY.as_bytes()),
                    image_policy_sha384: "16".repeat(48),
                    challenge_sha384: "17".repeat(48),
                },
            };
            let expectations = || GrantExpectations {
                authority_public_key: authority.public_key().as_ref().try_into().unwrap(),
                audience: grant_statement.audience.clone(),
                authority: grant_statement.binding.authority.clone(),
                tenant: grant_statement.binding.tenant.clone(),
                profile_sha384: grant_statement.binding.profile_sha384.clone(),
                launch_policy_sha384: grant_statement.binding.launch_policy_sha384.clone(),
                image_policy_sha384: grant_statement.binding.image_policy_sha384.clone(),
            };
            let grant_wire = serde_json::to_vec(&Signed {
                statement: grant_statement.clone(),
                signature: hex::encode(
                    authority
                        .sign(&grant_statement.signing_bytes().unwrap())
                        .as_ref(),
                ),
            })
            .unwrap();
            let grant = verify_launch_grant(&grant_wire, &expectations(), 1000).unwrap();
            let clock = Arc::new(ManualClock(Mutex::new(Ok(1000))));
            let sessions = gcp_launch_session::FreshLaunchSessions::new(
                gcp_launch_session::SessionConfig {
                    grant_expectations: expectations(),
                    boot_binding: binding(),
                    boot_policy: boot_policy(),
                    module_policy: module_policy(),
                    selected_policy_id: "launch_cpu".into(),
                    reference_data: None,
                    capacity: 8,
                },
                clock.clone(),
            )
            .unwrap();
            let as_engine = PolicyEngine::new(Arc::new(MemoryKeyValueStorage::default()));
            as_engine
                .set_policy("launch_cpu", AS_POLICY, true)
                .await
                .unwrap();
            let resource_engine = PolicyEngine::new(storage);
            resource_engine
                .set_policy("restricted_resource", RESOURCE_POLICY, true)
                .await
                .unwrap();
            let resource = gcp_launch_resource::LaunchResourceService::new(
                gcp_launch_resource::LaunchResourceConfig {
                    sessions: sessions.clone(),
                    engine: resource_engine.clone(),
                    policy_id: "restricted_resource".into(),
                    policy_sha384: hash(RESOURCE_POLICY.as_bytes()),
                    signer: proof,
                    audience: "policy-auditor".into(),
                    issuer: "kbs-proof-fixture".into(),
                    profile: POLICY_AGGREGATE_PROFILE.into(),
                    capacity: 8,
                },
            )
            .unwrap();
            Self {
                sessions,
                resource,
                clock,
                recorder,
                recorder_pkcs8,
                authority_public,
                #[cfg(feature = "launch-gcp-credentials")]
                authority_pkcs8,
                recorder_public,
                proof_public,
                #[cfg(feature = "launch-gcp-credentials")]
                proof_pkcs8,
                grant,
                grant_statement,
                grant_wire,
                keywrap,
                as_engine,
                resource_engine,
                provider: KvStorageProvider::new(StorageBackendConfig::default()),
            }
        }
        pub fn operation_signature(&self, operation: &SessionOperation) -> String {
            hex::encode(
                self.recorder
                    .sign(&operation_signing_bytes(&self.grant, &binding(), operation).unwrap())
                    .as_ref(),
            )
        }
        pub fn begin_signature(&self) -> String {
            self.operation_signature(&SessionOperation::Begin {
                key_sha384: hash(&serde_json_canonicalizer::to_vec(&self.keywrap).unwrap()),
            })
        }
        pub fn begin(&self) -> gcp_launch_session::FreshChallenge {
            self.sessions
                .begin_authenticated(
                    &self.grant_wire,
                    &self.keywrap,
                    &self.recorder_public,
                    &self.begin_signature(),
                )
                .unwrap()
        }
        pub fn capture_signature(
            &self,
            challenge: &gcp_launch_session::FreshChallenge,
            evidence: &[u8],
        ) -> String {
            let bytes = recorder_session_signing_bytes(
                &self.grant,
                &binding(),
                challenge.expected_quote().nonce(),
                &hash(challenge.expected_quote().canonical_runtime()),
                &hash(evidence),
            )
            .unwrap();
            hex::encode(self.recorder.sign(&bytes).as_ref())
        }
        pub async fn appraise(
            &self,
            challenge: &gcp_launch_session::FreshChallenge,
            evidence: &[u8],
        ) -> gcp_launch_evidence::AppraisedGcpLaunch {
            gcp_launch_evidence::test_support::appraise_software(
                challenge.expected_quote().clone(),
                evidence,
                &self.as_engine,
                "launch_cpu",
                None,
            )
            .await
            .unwrap()
        }
        pub async fn capture_software(&self) -> (gcp_launch_session::FreshChallenge, Vec<u8>) {
            let challenge = self.begin();
            let evidence =
                gcp_launch_evidence::test_support::evidence_bytes(challenge.expected_quote());
            let appraisal = self.appraise(&challenge, &evidence).await;
            let outcome = self
                .sessions
                .capture_with_test_appraisal(
                    challenge.session_id(),
                    &evidence,
                    &self.recorder_public,
                    &self.capture_signature(&challenge, &evidence),
                    appraisal,
                )
                .unwrap();
            assert!(matches!(
                outcome,
                gcp_launch_session::CaptureOutcome::Captured(_)
            ));
            (challenge, evidence)
        }
        pub fn resource_challenge_signature(
            &self,
            challenge: &gcp_launch_session::FreshChallenge,
            evidence: &[u8],
        ) -> String {
            self.operation_signature(&SessionOperation::ResourceChallenge {
                session_id: challenge.session_id().into(),
                nonce: challenge.expected_quote().nonce().into(),
                runtime_sha384: hash(challenge.expected_quote().canonical_runtime()),
                evidence_sha384: hash(evidence),
            })
        }
        pub fn resource_challenge(
            &self,
            challenge: &gcp_launch_session::FreshChallenge,
            evidence: &[u8],
        ) -> gcp_launch_resource::ResourceChallenge {
            self.resource
                .challenge(
                    challenge.session_id(),
                    &self.recorder_public,
                    &self.resource_challenge_signature(challenge, evidence),
                )
                .unwrap()
        }
        pub fn request(
            &self,
            challenge: &gcp_launch_resource::ResourceChallenge,
        ) -> ResourcePolicyRequest {
            ResourcePolicyRequest {
                method: "GET".into(),
                plugin: "resource".into(),
                resource_path: ["tenant-1".into(), "image-key".into(), "v1".into()],
                workflow_id: "image-decrypt-policy".into(),
                request_nonce: challenge.nonce().into(),
            }
        }
        pub fn decision_signature(
            &self,
            challenge: &gcp_launch_resource::ResourceChallenge,
            request: &ResourcePolicyRequest,
        ) -> String {
            self.operation_signature(&SessionOperation::ResourceDecision {
                session_id: challenge.session_id().into(),
                nonce: challenge.nonce().into(),
                runtime_sha384: challenge.runtime_sha384().into(),
                evidence_sha384: challenge.evidence_sha384().into(),
                request_sha384: request.digest_sha384().unwrap(),
            })
        }
        pub fn http_service(&self) -> actix_web::web::Data<gcp_launch_http::LaunchHttpService> {
            actix_web::web::Data::new(
                gcp_launch_http::LaunchHttpService::new(
                    self.sessions.clone(),
                    gcp_launch_http::LaunchHttpBackend {
                        verifier_config: None,
                        storage: self.provider.clone(),
                        engine: self.as_engine.clone(),
                    },
                    self.resource.clone(),
                )
                .unwrap(),
            )
        }
    }
}

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use execution_proof_contract::{
    gcp_credential::{verify_credential_delivery, GcpDeliveryExpectations},
    gcp_policy_receipt::{
        verify_policy_aggregate, GcpAggregateExpectations, GcpLaunchPolicyAggregateV2,
    },
    gcp_session::{operation_signing_bytes, SessionOperation},
    Signed,
};
use fixture::*;
use gcp_launch_credential::*;
use openssl::{
    encrypt::Decrypter,
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::{Padding, Rsa},
    symm::{decrypt_aead, Cipher},
};
use std::sync::Arc;

fn recipient() -> (PKey<Private>, kbs_types::TeePubKey) {
    let r = Rsa::generate(2048).unwrap();
    let public = kbs_types::TeePubKey::RSA {
        alg: "RSA-OAEP-256".into(),
        k_mod: URL_SAFE_NO_PAD.encode(r.n().to_vec()),
        k_exp: URL_SAFE_NO_PAD.encode(r.e().to_vec()),
    };
    (PKey::from_rsa(r).unwrap(), public)
}
fn decrypt(private: &PKey<Private>, bundle: &CredentialBundle) -> Vec<u8> {
    let response: kbs_types::Response = serde_json::from_slice(bundle.jwe_json()).unwrap();
    let mut rsa = Decrypter::new(private).unwrap();
    rsa.set_rsa_padding(Padding::PKCS1_OAEP).unwrap();
    rsa.set_rsa_oaep_md(MessageDigest::sha256()).unwrap();
    rsa.set_rsa_mgf1_md(MessageDigest::sha256()).unwrap();
    let mut cek = vec![0; rsa.decrypt_len(&response.encrypted_key).unwrap()];
    let n = rsa.decrypt(&response.encrypted_key, &mut cek).unwrap();
    cek.truncate(n);
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
async fn gcp_signed_policy_actual_jwe_and_live_cached_retry_then_expiry() {
    let (private, public) = recipient();
    let f = Fixture::with_resource_storage_and_keywrap(
        Arc::new(key_value_storage::memory::MemoryKeyValueStorage::default()),
        public,
    )
    .await;
    let (session, evidence) = f.capture_software().await;
    let c = f.resource_challenge(&session, &evidence);
    let request = f.request(&c);
    let signature = f.decision_signature(&c, &request);
    let bytes = match f
        .resource
        .decide(
            session.session_id(),
            &request,
            &f.recorder_public,
            &signature,
        )
        .await
        .unwrap()
    {
        gcp_launch_resource::ResourceOutcome::Current(v) => v,
        _ => panic!("expected a new resource policy decision"),
    };
    let signed: Signed<GcpLaunchPolicyAggregateV2> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        signed.statement.boot_binding_sha384,
        binding().digest_sha384().unwrap()
    );
    assert_eq!(signed.statement.grant_sha384, f.grant.grant_digest());
    assert_eq!(
        signed.statement.runtime_sha384,
        hash(session.expected_quote().canonical_runtime())
    );
    assert_eq!(
        signed.statement.as_evaluation.policy_sha384,
        hash(AS_POLICY.as_bytes())
    );
    assert_eq!(
        signed.statement.kbs_evaluation.policy_sha384,
        hash(RESOURCE_POLICY.as_bytes())
    );
    assert!(signed.statement.request == request);
    let roots = || GcpAggregateExpectations {
        kbs_proof_public_key: f.proof_public,
        boot_binding: binding(),
        expected: signed.statement.clone(),
    };
    let aggregate = verify_policy_aggregate(&bytes, &f.grant, &roots()).unwrap();
    let storage = ResourceStorage::new(
        credential_resource_backend::RepositoryConfig::KvStorage,
        f.provider.clone(),
    )
    .await
    .unwrap();
    let path = ["tenant-1", "image-key", "v1"];
    const SECRET: &[u8] = b"software-only-ephemeral-credential-not-real-cloud-key";
    storage
        .set_secret_resource(
            ResourceDesc {
                repository_name: path[0].into(),
                resource_type: path[1].into(),
                resource_tag: path[2].into(),
            },
            SECRET,
        )
        .await
        .unwrap();
    let service = LaunchCredentialService::new(LaunchCredentialConfig {
        resource: f.resource.clone(),
        storage,
        resource_path: path.map(str::to_owned),
        workflow_id: "image-decrypt-policy".into(),
        signer: ring::signature::Ed25519KeyPair::from_pkcs8(&f.proof_pkcs8).unwrap(),
        audience: "credential-client".into(),
        issuer: "kbs-proof-fixture".into(),
        capacity: 8,
    })
    .unwrap();
    let delivery_pop = f.operation_signature(&SessionOperation::CredentialDelivery {
        session_id: session.session_id().into(),
        nonce: c.nonce().into(),
        runtime_sha384: c.runtime_sha384().into(),
        evidence_sha384: c.evidence_sha384().into(),
        request_sha384: request.digest_sha384().unwrap(),
        aggregate_sha384: aggregate.digest_sha384().into(),
    });
    let bundle = match service
        .deliver(
            session.session_id(),
            aggregate.digest_sha384(),
            &f.recorder_public,
            &delivery_pop,
        )
        .await
        .unwrap()
    {
        CredentialOutcome::Current(v) => v,
        _ => panic!("expected a new credential delivery"),
    };
    let expected = GcpDeliveryExpectations {
        aggregate: roots(),
        audience: "credential-client".into(),
        issuer: "kbs-proof-fixture".into(),
        keywrap_sha384: hash(&serde_json_canonicalizer::to_vec(&f.keywrap).unwrap()),
    };
    let verified = verify_credential_delivery(
        bundle.signed_delivery_json(),
        &f.grant,
        &aggregate,
        &expected,
        bundle.jwe_json(),
        1000,
    )
    .unwrap();
    assert_eq!(
        verified.statement().boot_binding_sha384,
        binding().digest_sha384().unwrap()
    );
    assert_eq!(decrypt(&private, &bundle), SECRET);
    assert!(!String::from_utf8_lossy(bundle.signed_delivery_json())
        .contains(std::str::from_utf8(SECRET).unwrap()));
    let retry = match service
        .deliver(
            session.session_id(),
            aggregate.digest_sha384(),
            &f.recorder_public,
            &delivery_pop,
        )
        .await
        .unwrap()
    {
        CredentialOutcome::Existing(v) => v,
        _ => panic!("expected the cached credential delivery"),
    };
    assert!(Arc::ptr_eq(&retry, &bundle));
    let mut wrong = roots();
    wrong.boot_binding.config_sha384 = "ac".repeat(48);
    assert!(verify_policy_aggregate(&bytes, &f.grant, &wrong).is_err());
    f.clock.set(Ok(1031));
    assert!(matches!(
        service
            .deliver(
                session.session_id(),
                aggregate.digest_sha384(),
                &f.recorder_public,
                &delivery_pop
            )
            .await,
        Err(CredentialError::Resource(
            gcp_launch_resource::ResourceError::Session(gcp_launch_session::SessionError::Expired)
        ))
    ));
    assert!(matches!(
        f.resource
            .decide(
                session.session_id(),
                &request,
                &f.recorder_public,
                &signature
            )
            .await
            .unwrap(),
        gcp_launch_resource::ResourceOutcome::Historical(_)
    ));
    // Mutating both policy stores after completion must not replace retained
    // same-evaluation snapshots, including historical inspection after expiry.
    f.resource_engine
        .set_policy(
            "restricted_resource",
            "package policy\nallow := false\n",
            true,
        )
        .await
        .unwrap();
    f.as_engine
        .set_policy(
            "launch_cpu",
            "package policy\nlaunch_accepted := false\n",
            true,
        )
        .await
        .unwrap();
    let export = f
        .resource
        .export_policy_capture(session.session_id(), aggregate.digest_sha384())
        .unwrap();
    assert_eq!(export.as_capture().policy_bytes(), AS_POLICY.as_bytes());
    assert_eq!(
        export.kbs_capture().policy_bytes(),
        RESOURCE_POLICY.as_bytes()
    );
    assert_eq!(
        hash(export.as_capture().input_bytes()),
        signed.statement.as_evaluation.input_sha384
    );
    assert_eq!(
        hash(export.kbs_capture().input_bytes()),
        signed.statement.kbs_evaluation.input_sha384
    );
    assert_eq!(
        export.kbs_capture().data_bytes().map(hash),
        signed.statement.kbs_evaluation.data_sha384
    );
    let kbs_input: serde_json::Value =
        serde_json::from_slice(export.kbs_capture().input_bytes()).unwrap();
    let kbs_data: serde_json::Value =
        serde_json::from_slice(export.kbs_capture().data_bytes().unwrap()).unwrap();
    assert_eq!(
        kbs_input["verified_launch"]["boot_binding_sha384"],
        binding().digest_sha384().unwrap()
    );
    assert_eq!(kbs_data["resource-path"], serde_json::json!(path));
    assert_eq!(export.signed_aggregate_json(), bytes.as_ref());
    assert!(matches!(
        f.resource
            .export_policy_capture(&"ab".repeat(32), aggregate.digest_sha384()),
        Err(gcp_launch_resource::ResourceError::NotFound)
    ));
    assert!(matches!(
        f.resource
            .export_policy_capture(session.session_id(), &"ab".repeat(48)),
        Err(gcp_launch_resource::ResourceError::Conflict)
    ));
    let retry_export = f
        .resource
        .export_policy_capture(session.session_id(), aggregate.digest_sha384())
        .unwrap();
    assert!(std::ptr::eq(
        export.kbs_capture(),
        retry_export.kbs_capture()
    ));
    assert!(std::ptr::eq(export.as_capture(), retry_export.as_capture()));
    assert!(!String::from_utf8_lossy(export.kbs_capture().input_bytes())
        .contains(std::str::from_utf8(SECRET).unwrap()));
}

#[tokio::test]
async fn new_namespace_pop_retry_conflict_and_cancel_keep_attempt_terminal() {
    let f = Fixture::new().await;
    let session = f.begin();
    assert_eq!(f.begin().session_id(), session.session_id());
    let legacy = execution_proof_contract::session::operation_signing_bytes(
        &f.grant,
        &SessionOperation::Begin {
            key_sha384: hash(&serde_json_canonicalizer::to_vec(&f.keywrap).unwrap()),
        },
    )
    .unwrap();
    let wrong = hex::encode(f.recorder.sign(&legacy).as_ref());
    assert!(matches!(
        f.sessions
            .begin_authenticated(&f.grant_wire, &f.keywrap, &f.recorder_public, &wrong),
        Err(gcp_launch_session::SessionError::InvalidPossession)
    ));
    let mut key = f.keywrap.clone();
    if let kbs_types::TeePubKey::RSA { k_mod, .. } = &mut key {
        *k_mod = "BAUG".into();
    }
    let op = SessionOperation::Begin {
        key_sha384: hash(&serde_json_canonicalizer::to_vec(&key).unwrap()),
    };
    let signature = hex::encode(
        f.recorder
            .sign(&operation_signing_bytes(&f.grant, &binding(), &op).unwrap())
            .as_ref(),
    );
    assert!(matches!(
        f.sessions
            .begin_authenticated(&f.grant_wire, &key, &f.recorder_public, &signature),
        Err(gcp_launch_session::SessionError::Conflict)
    ));
    let evidence = gcp_launch_evidence::test_support::evidence_bytes(session.expected_quote());
    let signature = f.capture_signature(&session, &evidence);
    let inflight = f
        .sessions
        .start_test_capture(
            session.session_id(),
            &evidence,
            &f.recorder_public,
            &signature,
        )
        .unwrap();
    drop(inflight);
    assert!(matches!(
        f.sessions.start_test_capture(
            session.session_id(),
            &evidence,
            &f.recorder_public,
            &signature
        ),
        Err(gcp_launch_session::SessionError::Rejected)
    ));
    assert!(matches!(
        f.sessions.begin_authenticated(
            &f.grant_wire,
            &f.keywrap,
            &f.recorder_public,
            &f.begin_signature()
        ),
        Err(gcp_launch_session::SessionError::Rejected)
    ));
}

#[actix_web::test]
async fn http_v2_domain_checks_and_server_nonce_agree_with_actual_client() {
    use actix_web::{http::StatusCode, test, App};
    use execution_proof_client::gcp::*;
    let f = Fixture::new().await;
    let mut client = GcpClientProtocol::new(
        f.grant_wire.clone(),
        &execution_proof_contract::GrantExpectations {
            authority_public_key: f.authority_public,
            audience: f.grant_statement.audience.clone(),
            authority: f.grant_statement.binding.authority.clone(),
            tenant: f.grant_statement.binding.tenant.clone(),
            profile_sha384: f.grant_statement.binding.profile_sha384.clone(),
            launch_policy_sha384: f.grant_statement.binding.launch_policy_sha384.clone(),
            image_policy_sha384: f.grant_statement.binding.image_policy_sha384.clone(),
        },
        1000,
        ring::signature::Ed25519KeyPair::from_pkcs8(&f.recorder_pkcs8).unwrap(),
        f.keywrap.clone(),
        binding(),
    )
    .unwrap();
    let app = test::init_service(
        App::new()
            .app_data(f.http_service())
            .configure(gcp_launch_http::configure),
    )
    .await;
    let request = client.begin_request().unwrap();
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/kbs/launch/gcp/v2/begin")
            .set_payload(request.clone())
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = test::read_body(response).await;
    client.accept_begin_response(&body).unwrap();
    assert_eq!(
        client.report_data_full64().unwrap().as_slice(),
        f.begin().expected_quote().report_data()
    );
    for field in ["version", "purpose", "boot_binding_sha384"] {
        let mut wrong: serde_json::Value = serde_json::from_slice(&request).unwrap();
        wrong[field] = if field == "version" {
            1.into()
        } else {
            "wrong-peer".into()
        };
        let response = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/kbs/launch/gcp/v2/begin")
                .set_json(wrong)
                .to_request(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let missing = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/kbs/launch/v1/begin")
            .set_payload(request)
            .to_request(),
    )
    .await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    // Independent session owners cannot be silently combined in an HTTP service.
    let other = Fixture::new().await;
    assert!(gcp_launch_http::LaunchHttpService::new(
        other.sessions,
        gcp_launch_http::LaunchHttpBackend {
            verifier_config: None,
            storage: f.provider.clone(),
            engine: f.as_engine.clone()
        },
        f.resource.clone()
    )
    .is_err());
}
