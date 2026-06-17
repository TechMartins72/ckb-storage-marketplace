//! proof-verifier — CKB Type Script
//!
//! Validates a provider's Merkle proof-of-possession for a storage deal.
//!
//! Transaction shape expected:
//!   Inputs:
//!     [0] Deal cell       (deal-lock, proof-verifier type)
//!     [1] Escrow cell     (escrow-lock)
//!   Outputs:
//!     [0] Deal cell       (same type script; updated last_proof_epoch + state)
//!     [1] Provider payment output (plain CKB to provider_lock)
//!     [2] Escrow cell remainder   (escrow-lock; reduced by price_per_epoch)
//!   Header deps:
//!     [0] Block header from the challenge epoch (used for challenge index)
//!   Witnesses:
//!     [0] ProofSubmission (serialized per generated/types.rs layout)

#![no_std]
#![no_main]

use ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::*,
    default_alloc,
    entry,
    high_level::{
        load_cell_data, load_cell_lock_hash, load_cell_capacity,
        load_header, load_witness_args,
    },
    debug,
};

use ckb_hash::new_blake2b; 


entry!(program_entry);
default_alloc!();

include!("../../generated/types.rs");

// ---------------------------------------------------------------------------
// BLAKE2b-256 via ckb_std 0.14 (blake2b-ref crate, CKB personalisation)
// ---------------------------------------------------------------------------

fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut hasher = new_blake2b();
    hasher.update(data);
    hasher.finalize(&mut result);
    result
}

fn xor_bytes32(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

// ---------------------------------------------------------------------------
// Challenge index derivation
//   challenge_index = u64_le( block_hash XOR deal_outpoint_tx_hash ) % num_chunks
// ---------------------------------------------------------------------------

fn compute_challenge_index(
    block_hash: &[u8],
    deal_tx_hash: &[u8],
    num_chunks: u64,
) -> u64 {
    let xored = xor_bytes32(block_hash, deal_tx_hash);
    let raw = u64_from_le(&xored[0..8]);
    raw % num_chunks
}

// ---------------------------------------------------------------------------
// Merkle verification
//   Start from leaf_data_hash, walk siblings up to the root.
// ---------------------------------------------------------------------------

fn verify_merkle_proof(
    leaf_hash:   &[u8; 32],
    merkle_path: &[MerklePathItem],
    expected_root: &[u8],
) -> bool {
    let mut current = *leaf_hash;

    for item in merkle_path {
        let combined: alloc::vec::Vec<u8> = if item.is_left {
            // sibling is left, current is right
            item.sibling_hash.iter().chain(current.iter()).copied().collect()
        } else {
            // current is left, sibling is right
            current.iter().chain(item.sibling_hash.iter()).copied().collect()
        };
        current = blake2b_256(&combined);
    }

    current.as_ref() == expected_root
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

fn program_entry() -> i8 {
    // 1. Load deal cell data from input[0]
    let deal_data_in = match load_cell_data(0, Source::Input) {
        Ok(d) => d,
        Err(_) => {
            debug!("proof-verifier: failed to load input deal cell data");
            return 1;
        }
    };

    let deal = match DealParams::from_slice(&deal_data_in) {
        Ok(d) => d,
        Err(_) => {
            debug!("proof-verifier: DealParams parse error");
            return 1;
        }
    };

    // 2. Deal must be active
    if deal.state() != STATE_ACTIVE {
        debug!("proof-verifier: deal is not in active state");
        return 1;
    }

    // 3. Load proof from witness[0]
    let witness = match load_witness_args(0, Source::Input) {
        Ok(w) => w,
        Err(_) => {
            debug!("proof-verifier: failed to load witness");
            return 1;
        }
    };

    let input_type = match witness.input_type().to_opt() {
        Some(t) => t,
        None => {
            debug!("proof-verifier: no input_type in witness");
            return 1;
        }
    };

    let proof = match ProofSubmission::from_slice(&input_type.raw_data()) {
        Ok(p) => p,
        Err(_) => {
            debug!("proof-verifier: ProofSubmission parse error");
            return 1;
        }
    };

    // 4. Load block header from header_dep[0] (must be the challenge-epoch block)
    let header = match load_header(0, Source::HeaderDep) {
        Ok(h) => h,
        Err(_) => {
            debug!("proof-verifier: failed to load header dep");
            return 1;
        }
    };

    let block_hash_raw = header.calc_header_hash();
    let block_hash = block_hash_raw.as_slice();

    // 5. Verify challenge epoch matches the header's epoch
    let header_epoch_number = {
        let epoch_with_fraction = header.raw().epoch().unpack();
        // CKB epoch is packed: [length:16][index:16][number:24]
        epoch_with_fraction & 0x00FF_FFFF
    };

    if proof.challenge_epoch != header_epoch_number {
        debug!("proof-verifier: challenge_epoch mismatch");
        return 1;
    }

    // 6. Verify the challenge epoch is within the window
    //    i.e., current_epoch <= last_proof_epoch + challenge_freq
    let expected_challenge_epoch = deal.last_proof_epoch() + deal.challenge_freq() as u64;
    if proof.challenge_epoch > expected_challenge_epoch {
        debug!("proof-verifier: proof submitted outside challenge window");
        return 1;
    }

    // 7. Recompute challenge index and verify it matches the submitted proof
    let num_chunks = deal.num_chunks();
    if num_chunks == 0 {
        debug!("proof-verifier: num_chunks is zero");
        return 1;
    }

    let expected_index = compute_challenge_index(block_hash, &proof.deal_tx_hash, num_chunks);
    if proof.challenge_index != expected_index {
        debug!("proof-verifier: challenge_index mismatch");
        return 1;
    }

    // 8. Verify Merkle proof
    let merkle_ok = verify_merkle_proof(
        &proof.leaf_data_hash,
        &proof.merkle_path,
        deal.merkle_root(),
    );

    if !merkle_ok {
        debug!("proof-verifier: Merkle proof verification failed");
        return 1;
    }

    // 9. Verify output deal cell has updated last_proof_epoch and correct state
    let deal_data_out = match load_cell_data(0, Source::Output) {
        Ok(d) => d,
        Err(_) => {
            debug!("proof-verifier: failed to load output deal cell data");
            return 1;
        }
    };

    let deal_out = match DealParams::from_slice(&deal_data_out) {
        Ok(d) => d,
        Err(e) => {
            debug!("proof-verifier: output DealParams parse error: {}", e);
            return 1;
        }
    };

    if deal_out.last_proof_epoch() != proof.challenge_epoch {
        debug!("proof-verifier: output deal cell has wrong last_proof_epoch");
        return 1;
    }

    // Check if deal is now complete (last proof covers last epoch)
    let end_epoch = deal.start_epoch() + deal.deal_duration();
    let expected_out_state = if proof.challenge_epoch >= end_epoch {
        STATE_COMPLETE
    } else {
        STATE_ACTIVE
    };

    if deal_out.state() != expected_out_state {
        debug!("proof-verifier: output deal cell has wrong state");
        return 1;
    }

    // 10. Verify the provider is paid price_per_epoch shannons
    //     output[1] must go to the provider lock hash
    let provider_out_capacity = match load_cell_capacity(1, Source::Output) {
        Ok(c) => c,
        Err(_) => {
            debug!("proof-verifier: failed to load provider payment output capacity");
            return 1;
        }
    };

    if provider_out_capacity < deal.price_per_epoch() {
        debug!("proof-verifier: provider payment output too small");
        return 1;
    }

    let provider_out_lock = match load_cell_lock_hash(1, Source::Output) {
        Ok(h) => h,
        Err(_) => {
            debug!("proof-verifier: failed to load provider payment output lock");
            return 1;
        }
    };

    if provider_out_lock.as_slice() != deal.provider_lock_hash() {
        debug!("proof-verifier: provider payment goes to wrong lock");
        return 1;
    }

    // All checks passed — proof is valid
    0
}
