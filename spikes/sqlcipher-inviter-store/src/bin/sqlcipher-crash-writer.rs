#![forbid(unsafe_code)]

use std::path::Path;

use sqlcipher_inviter_store_spike::{
    CommitFault, JoinCommit, Reservation, SqlCipherStore, StoreError, VaultKey,
};

const NOW: u64 = 1_000;

fn main() {
    let Some(path) = std::env::args_os().nth(1) else {
        std::process::exit(2);
    };
    if run(Path::new(&path)).is_err() {
        std::process::exit(3);
    }
}

fn run(path: &Path) -> Result<(), StoreError> {
    let mut store = SqlCipherStore::create(path, VaultKey::new([7; 32])?)?;
    let reservation = Reservation::new([1; 16], [2; 64], [3; 16], NOW + 300)?;
    store.seed_reservation(&reservation, NOW)?;
    let commit = JoinCommit::new(
        [4; 16],
        [1; 16],
        [2; 64],
        [3; 16],
        [10; 32],
        vec![5; 16],
        7,
        8,
        vec![6; 32],
        vec![7; 512],
        vec![8; 256],
        vec![9; 64],
        NOW + 120,
    );
    store.commit_join(&commit, NOW, CommitFault::ExitBeforeCommit)?;
    Err(StoreError::Rejected)
}
