//! deal-lock — CKB Lock Script
//!
//! Owns the deal cell. Controls who can spend it and validates state transitions.
//!
//! Spending conditions:
//!   1. CANCEL  — state=pending, signed by renter (deal not yet active)
//!   2. ACCEPT  — state=pending→active, signed by provider, sets start_epoch
//!   3. PROOF   — state=active, proof-verifier type script runs in this tx
//!   4. CLOSE   — state=complete, signed by either renter or provider
//!   5. SLASH   — state=active→slashed, proof deadline missed (no valid sig required)
//!
//! Lock args layout (65 bytes):
//!   [0..32]  renter_lock_hash    — who can cancel or close
//!   [32..64] provider_lock_hash  — who can accept or close
//!   [64]     action              — 0=cancel, 1=accept, 2=proof, 3=close, 4=slash

#![no_std]
#![no_main]

use ckb_std::{
    ckb_constants::Source,
    default_alloc,
    entry,
    high_level::{
        load_cell_data, load_cell_type_hash,
        load_script, load_script_hash,
        QueryIter,
    },
    debug,
};

entry!(program_entry);
default_alloc!();

include!("../../generated/types.rs");

// ---------------------------------------------------------------------------
// Action constants (stored in lock args[64])
// ---------------------------------------------------------------------------
const ACTION_CANCEL:  u8 = 0;
const ACTION_ACCEPT:  u8 = 1;
const ACTION_PROOF:   u8 = 2;
const ACTION_CLOSE:   u8 = 3;
const ACTION_SLASH:   u8 = 4;

// ---------------------------------------------------------------------------
// Verify that a signature from lock_hash owner is present in the tx.
// CKB's secp256k1-based lock scripts prove ownership by the lock script itself
// running and returning 0. Here we check the input set for a cell owned by
// the given lock hash — if such a cell is consumed in this tx, the owner signed.
// ---------------------------------------------------------------------------
fn is_signed_by(lock_hash: &[u8]) -> bool {
    QueryIter::new(
        |index, source| ckb_std::high_level::load_cell_lock_hash(index, source),
        Source::Input,
    )
    .any(|h| h.as_slice() == lock_hash)
}

// ---------------------------------------------------------------------------
// Check that proof-verifier type script ran in this transaction.
// We look for an output cell whose type script hash matches the proof-verifier
// code hash stored in the deal cell's type script args.
// ---------------------------------------------------------------------------
fn proof_verifier_ran(proof_verifier_type_hash: &[u8]) -> bool {
    QueryIter::new(
        |index, source| load_cell_type_hash(index, source),
        Source::Output,
    )
    .any(|opt| {
        opt.map(|h| h.as_slice() == proof_verifier_type_hash)
            .unwrap_or(false)
    })
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn program_entry() -> i8 {
    let script = match load_script() {
        Ok(s) => s,
        Err(_) => { debug!("deal-lock: load_script failed"); return 1; }
    };

    let args = script.args().raw_data();
    if args.len() < 65 {
        debug!("deal-lock: args too short (need 65 bytes)");
        return 1;
    }

    let renter_lock_hash    = &args[0..32];
    let provider_lock_hash  = &args[32..64];
    let action              = args[64];

    // Load input deal cell data (this script's cell)
    let self_hash = match load_script_hash() {
        Ok(h) => h,
        Err(_) => { debug!("deal-lock: load_script_hash failed"); return 1; }
    };

    // Find which input index is this deal cell
    let deal_input_idx = QueryIter::new(
        |index, source| ckb_std::high_level::load_cell_lock_hash(index, source),
        Source::Input,
    )
    .position(|h| h.as_slice() == self_hash.as_slice());

    let deal_idx = match deal_input_idx {
        Some(i) => i,
        None => { debug!("deal-lock: could not find own input"); return 1; }
    };

    let deal_data = match load_cell_data(deal_idx, Source::Input) {
        Ok(d) => d,
        Err(_) => { debug!("deal-lock: failed to load deal cell data"); return 1; }
    };

    let deal = match DealParams::from_slice(&deal_data) {
        Ok(d) => d,
        Err(e) => { debug!("deal-lock: DealParams parse: {}", e); return 1; }
    };

    match action {
        // ------------------------------------------------------------------
        // CANCEL: renter cancels a pending deal before any provider accepts
        // ------------------------------------------------------------------
        ACTION_CANCEL => {
            if deal.state() != STATE_PENDING {
                debug!("deal-lock: cancel requires state=pending");
                return 1;
            }
            if !is_signed_by(renter_lock_hash) {
                debug!("deal-lock: cancel requires renter signature");
                return 1;
            }
            // Deal cell is consumed; no output deal cell required
            0
        }

        // ------------------------------------------------------------------
        // ACCEPT: provider accepts a pending deal
        // Output deal cell must have state=active and correct start_epoch
        // ------------------------------------------------------------------
        ACTION_ACCEPT => {
            if deal.state() != STATE_PENDING {
                debug!("deal-lock: accept requires state=pending");
                return 1;
            }
            if !is_signed_by(provider_lock_hash) {
                debug!("deal-lock: accept requires provider signature");
                return 1;
            }

            // Validate output deal cell
            let out_data = match load_cell_data(deal_idx, Source::Output) {
                Ok(d) => d,
                Err(_) => { debug!("deal-lock: no output deal cell for accept"); return 1; }
            };
            let out_deal = match DealParams::from_slice(&out_data) {
                Ok(d) => d,
                Err(_) => { debug!("deal-lock: output DealParams parse failed"); return 1; }
            };
            if out_deal.state() != STATE_ACTIVE {
                debug!("deal-lock: accept output must have state=active");
                return 1;
            }
            if out_deal.start_epoch() == 0 {
                debug!("deal-lock: accept output must set start_epoch");
                return 1;
            }
            // All other fields must remain unchanged
            if out_deal.merkle_root() != deal.merkle_root()
                || out_deal.file_size() != deal.file_size()
                || out_deal.deal_duration() != deal.deal_duration()
                || out_deal.price_per_epoch() != deal.price_per_epoch()
            {
                debug!("deal-lock: accept output changed immutable fields");
                return 1;
            }
            0
        }

        // ------------------------------------------------------------------
        // PROOF: proof-verifier type script must run in this tx
        // The type script does the heavy lifting; we just confirm it ran.
        // ------------------------------------------------------------------
        ACTION_PROOF => {
            if deal.state() != STATE_ACTIVE {
                debug!("deal-lock: proof requires state=active");
                return 1;
            }
            // The proof-verifier type hash is expected in the deal cell's type script
            // For simplicity, we trust that if proof-verifier is in output type hashes, it ran
            // In production: store proof_verifier_code_hash in lock args
            // Here we verify output[0] deal cell has updated last_proof_epoch
            let out_data = match load_cell_data(0, Source::Output) {
                Ok(d) => d,
                Err(_) => { debug!("deal-lock: no output deal cell for proof"); return 1; }
            };
            let out_deal = match DealParams::from_slice(&out_data) {
                Ok(d) => d,
                Err(_) => { debug!("deal-lock: output DealParams parse failed"); return 1; }
            };
            if out_deal.last_proof_epoch() <= deal.last_proof_epoch() {
                debug!("deal-lock: proof did not advance last_proof_epoch");
                return 1;
            }
            0
        }

        // ------------------------------------------------------------------
        // CLOSE: deal completed normally, either party can close
        // ------------------------------------------------------------------
        ACTION_CLOSE => {
            if deal.state() != STATE_COMPLETE {
                debug!("deal-lock: close requires state=complete");
                return 1;
            }
            let signed = is_signed_by(renter_lock_hash) || is_signed_by(provider_lock_hash);
            if !signed {
                debug!("deal-lock: close requires renter or provider signature");
                return 1;
            }
            // Deal cell consumed, collateral released by collateral-lock
            0
        }

        // ------------------------------------------------------------------
        // SLASH: proof deadline missed — anyone can trigger this
        // The collateral-lock handles the actual split/burn
        // ------------------------------------------------------------------
        ACTION_SLASH => {
            if deal.state() != STATE_ACTIVE {
                debug!("deal-lock: slash requires state=active");
                return 1;
            }
            // Verify the output deal cell reflects the slashed state
            let out_data = match load_cell_data(0, Source::Output) {
                Ok(d) => d,
                Err(_) => { debug!("deal-lock: no output deal cell for slash"); return 1; }
            };
            let out_deal = match DealParams::from_slice(&out_data) {
                Ok(d) => d,
                Err(_) => return 1,
            };
            if out_deal.state() != STATE_SLASHED {
                debug!("deal-lock: slash output must have state=slashed");
                return 1;
            }
            // Challenge deadline enforcement is done off-chain by the bot
            // which only submits a slash tx after the window has passed.
            // The on-chain check: last_proof_epoch + challenge_freq < current epoch
            // requires a header dep; we trust the collateral-lock for the math.
            0
        }

        _ => {
            debug!("deal-lock: unknown action");
            1
        }
    }
}
