//! L2 case fixtures, baseline setup, and seeded fault mutations.

use super::*;

pub(super) struct CaseFixture {
    pub(super) invitation_id: [u8; 16],
    pub(super) invitation_generation: [u8; 64],
    pub(super) join_request_id: [u8; 16],
    pub(super) request_fingerprint: [u8; 32],
    pub(super) transaction_id: [u8; 16],
    pub(super) group_id: [u8; 32],
    pub(super) key_package_reference: [u8; 32],
    pub(super) credential_identity: [u8; 32],
}

impl CaseFixture {
    fn random() -> Result<Self, SessionCtlError> {
        Ok(Self {
            invitation_id: random_nonzero()?,
            invitation_generation: random_nonzero()?,
            join_request_id: random_nonzero()?,
            request_fingerprint: random_nonzero()?,
            transaction_id: random_nonzero()?,
            group_id: random_nonzero()?,
            key_package_reference: random_nonzero()?,
            credential_identity: random_nonzero()?,
        })
    }

    pub(super) fn encode(&self) -> Zeroizing<[u8; CASE_FIXTURE_BYTES]> {
        let mut bytes = Zeroizing::new([0_u8; CASE_FIXTURE_BYTES]);
        let mut offset = 0;
        for field in [
            CASE_FIXTURE_MAGIC.as_slice(),
            self.invitation_id.as_slice(),
            self.invitation_generation.as_slice(),
            self.join_request_id.as_slice(),
            self.request_fingerprint.as_slice(),
            self.transaction_id.as_slice(),
            self.group_id.as_slice(),
            self.key_package_reference.as_slice(),
            self.credential_identity.as_slice(),
        ] {
            bytes[offset..offset + field.len()].copy_from_slice(field);
            offset += field.len();
        }
        bytes
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, SessionCtlError> {
        if bytes.len() != CASE_FIXTURE_BYTES || &bytes[..8] != CASE_FIXTURE_MAGIC {
            return Err(stage("L2 fixture"));
        }
        let mut offset = 8;
        fn take<const N: usize>(
            bytes: &[u8],
            offset: &mut usize,
        ) -> Result<[u8; N], SessionCtlError> {
            let end = offset.checked_add(N).ok_or_else(|| stage("L2 fixture"))?;
            let value = bytes
                .get(*offset..end)
                .ok_or_else(|| stage("L2 fixture"))?
                .try_into()
                .map_err(|_| stage("L2 fixture"))?;
            *offset = end;
            Ok(value)
        }
        let fixture = Self {
            invitation_id: take(bytes, &mut offset)?,
            invitation_generation: take(bytes, &mut offset)?,
            join_request_id: take(bytes, &mut offset)?,
            request_fingerprint: take(bytes, &mut offset)?,
            transaction_id: take(bytes, &mut offset)?,
            group_id: take(bytes, &mut offset)?,
            key_package_reference: take(bytes, &mut offset)?,
            credential_identity: take(bytes, &mut offset)?,
        };
        if fixture.invitation_id.iter().all(|byte| *byte == 0)
            || fixture.invitation_generation.iter().all(|byte| *byte == 0)
            || fixture.join_request_id.iter().all(|byte| *byte == 0)
            || fixture.request_fingerprint.iter().all(|byte| *byte == 0)
            || fixture.transaction_id.iter().all(|byte| *byte == 0)
            || fixture.group_id.iter().all(|byte| *byte == 0)
            || fixture.key_package_reference.iter().all(|byte| *byte == 0)
            || fixture.credential_identity.iter().all(|byte| *byte == 0)
        {
            return Err(stage("L2 fixture"));
        }
        Ok(fixture)
    }
}

impl Drop for CaseFixture {
    fn drop(&mut self) {
        self.invitation_id.zeroize();
        self.invitation_generation.zeroize();
        self.join_request_id.zeroize();
        self.request_fingerprint.zeroize();
        self.transaction_id.zeroize();
        self.group_id.zeroize();
        self.key_package_reference.zeroize();
        self.credential_identity.zeroize();
    }
}

pub(super) fn read_fixture(root: &Path, name: &str) -> Result<CaseFixture, SessionCtlError> {
    let path = root.join(name);
    let bytes = Zeroizing::new(read_owned_file(&path, CASE_FIXTURE_BYTES)?);
    fs::remove_file(&path).map_err(|_| stage("L2 fixture cleanup"))?;
    CaseFixture::decode(&bytes)
}

pub(super) fn read_optional_welcome_canary(
    root: &Path,
) -> Result<Option<Zeroizing<Vec<u8>>>, SessionCtlError> {
    let path = root.join(WELCOME_FIXTURE_NAME);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(Zeroizing::new(read_bounded_owned_file(
        &path, 65_536,
    )?)))
}

pub(super) fn prepare_baseline(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    scenario: Scenario,
) -> Result<CaseFixture, SessionCtlError> {
    let mut fixture = CaseFixture::random()?;
    let storage = SqlCipherStorage::create(
        &root.join(DATABASE_NAME),
        VaultKey::new(**key).map_err(|_| stage("L2 baseline"))?,
    )
    .map_err(|_| stage("L2 baseline"))?;
    let group_id = SessionGroupId::new(fixture.group_id).map_err(|_| stage("L2 baseline"))?;
    match scenario {
        Scenario::InviterTransaction => {
            storage
                .seed_reservation(
                    fixture.invitation_id,
                    fixture.invitation_generation,
                    fixture.join_request_id,
                    RESERVATION_EXPIRES_AT,
                    BASELINE_NOW,
                )
                .map_err(|_| stage("L2 baseline"))?;
            let client = create_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 baseline identity"))?;
            fixture.credential_identity = *client.credential_identity().as_bytes();
            if client
                .credential_identity()
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            {
                return Err(stage("L2 baseline identity"));
            }
        }
        Scenario::JoinerTransaction => {
            let bob = create_durable_client_with_storage(
                group_id,
                storage.clone(),
                storage.clone(),
                storage.clone(),
            )
            .map_err(|_| stage("L2 baseline identity"))?;
            fixture.credential_identity = *bob.credential_identity().as_bytes();
            let key_package = bob
                .generate_key_package(BASELINE_NOW)
                .map_err(|_| stage("L2 baseline KeyPackage"))?;
            let validated = create_key_package_validator()
                .validate_key_package(key_package.as_bytes(), BASELINE_NOW)
                .map_err(|_| stage("L2 baseline KeyPackage"))?;
            fixture.key_package_reference = *validated.key_package_reference();
            let alice = create_client().map_err(|_| stage("L2 baseline Alice"))?;
            let mut group = alice
                .create_group(group_id, BASELINE_NOW)
                .map_err(|_| stage("L2 baseline group"))?;
            let welcome = group
                .prepare_add(validated, BASELINE_NOW)
                .map_err(|_| stage("L2 baseline Add"))?
                .apply()
                .map_err(|_| stage("L2 baseline Add"))?
                .into_welcome();
            write_bounded_owned_file(
                &root.join(WELCOME_FIXTURE_NAME),
                welcome.as_bytes(),
                true,
                65_536,
            )?;
        }
    }
    drop(storage);
    Ok(fixture)
}

pub(super) fn inject_mixed_group(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
) -> Result<(), SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    connection
        .execute(
            "INSERT INTO mls_groups(group_id, state) VALUES (?1, ?2)",
            params![fixture.group_id, [0x41_u8]],
        )
        .map_err(|_| stage("L2 mixed fixture"))?;
    Ok(())
}

pub(super) fn inject_identity_loss(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
) -> Result<(), SessionCtlError> {
    open_keyed_connection(&root.join(DATABASE_NAME), key)?
        .execute("DELETE FROM mls_client_identity", [])
        .map_err(|_| stage("L2 identity defect"))?;
    Ok(())
}

pub(super) fn inject_reservation_substitution(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
) -> Result<(), SessionCtlError> {
    let substitute: [u8; 16] = random_nonzero()?;
    open_keyed_connection(&root.join(DATABASE_NAME), key)?
        .execute(
            "UPDATE reservations SET join_request_id = ?1 WHERE invitation_id = ?2",
            params![substitute, fixture.invitation_id],
        )
        .map_err(|_| stage("L2 reservation defect"))?;
    Ok(())
}

pub(super) fn inject_defective_schema(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
) -> Result<(), SessionCtlError> {
    open_keyed_connection(&root.join(DATABASE_NAME), key)?
        .execute_batch("ALTER TABLE reservations RENAME COLUMN expires_at TO expires_at_defective;")
        .map_err(|_| stage("L2 schema defect"))
}

pub(super) fn inject_inviter_lifecycle_defect(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
    defect: &str,
) -> Result<(), SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    let sql = match defect {
        "lease_generation" => {
            "UPDATE inviter_joins SET lease_generation = 1 WHERE transaction_id = ?1"
        }
        "attempt_ceiling" => {
            "UPDATE inviter_joins SET maximum_delivery_attempts = 4 WHERE transaction_id = ?1"
        }
        _ => return Err(stage("L2 lifecycle defect")),
    };
    if connection
        .execute(sql, params![fixture.transaction_id])
        .map_err(|_| stage("L2 lifecycle defect"))?
        != 1
    {
        return Err(stage("L2 lifecycle defect"));
    }
    Ok(())
}

pub(super) fn inject_joiner_retained_key_package(
    root: &Path,
    key: &Zeroizing<[u8; KEY_BYTES]>,
    fixture: &CaseFixture,
) -> Result<(), SessionCtlError> {
    let connection = open_keyed_connection(&root.join(DATABASE_NAME), key)?;
    if connection
        .execute(
            "INSERT INTO key_packages(
                 key_package_ref, key_package, init_key, leaf_key, expires_at
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                fixture.key_package_reference,
                [0x4b_u8],
                [0x49_u8],
                [0x4c_u8],
                (BASELINE_NOW + 600) as i64,
            ],
        )
        .map_err(|_| stage("L2 retained KeyPackage defect"))?
        != 1
    {
        return Err(stage("L2 retained KeyPackage defect"));
    }
    Ok(())
}
