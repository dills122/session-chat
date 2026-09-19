//! L2 writer role and real storage transaction application.

use super::fixtures::{CaseFixture, read_fixture};
use super::model::L2HarnessProbe;
use super::resources::{
    StdioBarrier, read_bounded_owned_file_once, read_case_config, read_key,
    write_bounded_owned_file,
};
use super::{
    APPROVAL_RECORD, BASELINE_NOW, DATABASE_NAME, MAX_CHILD_OUTPUT_BYTES, OUTBOX_EXPIRES_AT,
    WELCOME_FIXTURE_NAME, WRITER_CASE_FIXTURE_NAME, WRITER_KEY_NAME,
};
use crate::{SessionCtlError, stage};
use session_crypto_mls::{
    SessionGroupId, WelcomeMessage, create_client, create_key_package_validator,
    load_durable_client_with_storage,
};
use session_protocol::{DepositCapability, LocalWelcomeDepositEndpoint, OpaqueEnvelope};
use std::io::Write;
use std::path::Path;
use std::thread;
use std::time::Duration;
use storage_sqlcipher::fault_testing;
use storage_sqlcipher::fault_testing::{Checkpoint, ControlFrame, FaultObserver, Scenario};
use storage_sqlcipher::{
    InviterJoinTransaction, JoinerTransaction, PersistenceFault, SqlCipherStorage, StoreError,
    VaultKey,
};

pub(super) fn run_writer(root: &Path) -> Result<(), SessionCtlError> {
    let config = read_case_config(root)?;
    let fixture = read_fixture(root, WRITER_CASE_FIXTURE_NAME)?;
    let key = read_key(root, WRITER_KEY_NAME)?;
    let transport = std::sync::Arc::new(StdioBarrier::default());
    let observer = FaultObserver::new(config.target.case_id(), config.target.scenario(), transport);
    let storage = fault_testing::open(
        &root.join(DATABASE_NAME),
        VaultKey::new(*key).map_err(|_| stage("L2 writer"))?,
        observer.clone(),
    )
    .map_err(|_| stage("L2 writer"))?;

    match config.probe {
        L2HarnessProbe::GracefulContinue
        | L2HarnessProbe::KillWhileBlocked
        | L2HarnessProbe::MixedFixture
        | L2HarnessProbe::IdentityLoss
        | L2HarnessProbe::ReservationSubstitution
        | L2HarnessProbe::DefectiveSchema
        | L2HarnessProbe::LingeringHandle
        | L2HarnessProbe::NonzeroLeaseGeneration
        | L2HarnessProbe::ChangedAttemptCeiling
        | L2HarnessProbe::InviterRetryMutation
        | L2HarnessProbe::JoinerRetryMutation
        | L2HarnessProbe::JoinerRetainedKeyPackage
        | L2HarnessProbe::MissingAcknowledgement => run_real_storage_transaction(
            &storage,
            observer,
            config.target.scenario(),
            &fixture,
            root,
        ),
        L2HarnessProbe::IoFault => Err(stage("L2 writer mode")),
        L2HarnessProbe::SecretDiagnostic => {
            eprintln!("seeded-secret-diagnostic");
            observer
                .checkpoint(config.target.checkpoint(), config.target.occurrence())
                .map_err(|_| stage("L2 writer barrier"))
        }
        L2HarnessProbe::AdvanceWithoutAcknowledgement => {
            let next = ControlFrame::new_checkpoint(
                config.target.case_id(),
                Checkpoint::InviterAfterGroupUpsert,
                0,
            )
            .map_err(|_| stage("L2 writer frame"))?;
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(&config.target.encode())
                .and_then(|()| stdout.write_all(&next.encode()))
                .and_then(|()| stdout.flush())
                .map_err(|_| stage("L2 writer output"))?;
            thread::sleep(Duration::from_secs(10));
            Ok(())
        }
        L2HarnessProbe::OversizedOutput => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(&config.target.encode())
                .and_then(|()| stdout.write_all(&[0; MAX_CHILD_OUTPUT_BYTES + 1]))
                .and_then(|()| stdout.flush())
                .map_err(|_| stage("L2 writer output"))?;
            thread::sleep(Duration::from_secs(10));
            Ok(())
        }
        L2HarnessProbe::Stall => {
            thread::sleep(Duration::from_secs(10));
            Ok(())
        }
    }
}

pub(super) fn run_real_storage_transaction(
    storage: &SqlCipherStorage,
    observer: FaultObserver,
    scenario: Scenario,
    fixture: &CaseFixture,
    root: &Path,
) -> Result<(), SessionCtlError> {
    let group_id = SessionGroupId::new(fixture.group_id).map_err(|_| stage("L2 writer group"))?;
    match scenario {
        Scenario::InviterTransaction => {
            let alice = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 writer identity"))?;
            let mut group = alice
                .create_group(group_id, BASELINE_NOW)
                .map_err(|_| stage("L2 writer group"))?;
            let bob = create_client().map_err(|_| stage("L2 writer peer"))?;
            let key_package = bob
                .generate_key_package(BASELINE_NOW)
                .map_err(|_| stage("L2 writer KeyPackage"))?;
            let validated = create_key_package_validator()
                .validate_key_package(key_package.as_bytes(), BASELINE_NOW)
                .map_err(|_| stage("L2 writer KeyPackage"))?;
            let addition = group
                .prepare_add(validated, BASELINE_NOW)
                .map_err(|_| stage("L2 writer Add"))?
                .apply()
                .map_err(|_| stage("L2 writer Add"))?;
            let endpoint = fixture_endpoint()?;
            let persisted = addition
                .stage_and_write_to_storage(&mut group, |binding| {
                    let transaction = InviterJoinTransaction::new_bound(
                        fixture.transaction_id,
                        fixture.invitation_id,
                        fixture.invitation_generation,
                        fixture.join_request_id,
                        fixture.request_fingerprint,
                        fixture.group_id,
                        0,
                        1,
                        APPROVAL_RECORD.to_vec(),
                        [0x81; 16],
                        OUTBOX_EXPIRES_AT,
                        endpoint,
                        OUTBOX_EXPIRES_AT,
                    )
                    .map_err(|_| StoreError::Rejected)?;
                    storage.stage_bound_inviter(
                        binding,
                        transaction,
                        BASELINE_NOW,
                        PersistenceFault::None,
                    )
                })
                .map_err(|_| stage("L2 writer transaction"))?;
            let envelope = OpaqueEnvelope::new(
                [0x81; 16],
                OUTBOX_EXPIRES_AT,
                persisted.welcome().as_bytes().to_vec(),
            )
            .map_err(|_| stage("L2 writer Welcome"))?
            .encode_canonical()
            .map_err(|_| stage("L2 writer Welcome"))?;
            write_bounded_owned_file(&root.join(WELCOME_FIXTURE_NAME), &envelope, true, 65_536)?;
            observer
                .checkpoint(Checkpoint::InviterBeforeShadowFinalize, 0)
                .map_err(|_| stage("L2 writer barrier"))?;
        }
        Scenario::JoinerTransaction => {
            let bob = load_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 writer identity"))?;
            let welcome_bytes = read_bounded_owned_file_once(
                &root.join(WELCOME_FIXTURE_NAME),
                65_536,
                "L2 Welcome fixture cleanup",
            )?;
            let welcome = WelcomeMessage::from_bytes(&welcome_bytes)
                .map_err(|_| stage("L2 writer Welcome"))?;
            let mut group = bob
                .join_group(welcome, BASELINE_NOW)
                .map_err(|_| stage("L2 writer join"))?;
            storage
                .stage_joiner(
                    JoinerTransaction::new(
                        fixture.transaction_id,
                        fixture.group_id,
                        fixture.key_package_reference,
                    )
                    .map_err(|_| stage("L2 writer transaction"))?,
                    PersistenceFault::None,
                )
                .map_err(|_| stage("L2 writer transaction"))?;
            group
                .write_to_storage()
                .map_err(|_| stage("L2 writer transaction"))?;
        }
    }
    Ok(())
}

pub(super) fn fixture_endpoint() -> Result<Vec<u8>, SessionCtlError> {
    LocalWelcomeDepositEndpoint::new(
        [0x82; 16],
        [0x83; 16],
        DepositCapability::new([0x84; 32]).map_err(|_| stage("L2 endpoint"))?,
        OUTBOX_EXPIRES_AT,
    )
    .map_err(|_| stage("L2 endpoint"))?
    .encode_canonical()
    .map_err(|_| stage("L2 endpoint"))
}
