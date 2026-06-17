//! escrow-lock — CKB Lock Script
//!
//! Holds the renter's CKB payment for the entire deal duration.
//! Released incrementally to the provider each time a valid proof is accepted.
//!
//! Lock args layout (80 bytes):
//!   [0..32]   deal_cell_type_hash — identifies which deal this escrow belongs to
//!   [32..64]  renter_lock_hash    — refund destination
//!   [64..96]  provider_lock_hash  — payment destination
//!   NOTE: price_per_epoch is read from the deal cell, not from args, to avoid drift
//!
//! Spending conditions:
//!   1. PROOF_RELEASE  — proof-verifier ran; release price_per_epoch to provider
//!   2. REFUND         — deal cancelled/expired; return remaining to renter
//!   3. SLASH_REFUND   — deal slashed; escrow remainder returned to renter

#![no_std]
#![no_main]

use ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::*,
    default_alloc,
    entry,
    high_level::{
        load_cell_capacity, load_cell_data,
        load_cell_lock_hash, load_cell_type_hash,
        load_script,
    },
    debug,
};

entry!(program_entry);
default_alloc!();

include!("../../generated/types.rs");

const ESCROW_ARGS_LEN: usize = 96;

const ACTION_PROOF_RELEASE: u8 = 0;
const ACTION_REFUND:        u8 = 1;
const ACTION_SLASH_REFUND:  u8 = 2;

fn is_lock_in_outputs(lock_hash: &[u8], min_capacity: u64) -> bool {
    let mut idx = 0usize;
    loop {
        match load_cell_lock_hash(idx, Source::Output) {
            Ok(h) => {
                if h.as_slice() == lock_hash {
                    if let Ok(cap) = load_cell_capacity(idx, Source::Output) {
                        if cap >= min_capacity {
                            return true;
                        }
                    }
                }
            }
            Err(_) => break,
        }
        idx += 1;
    }
    false
}

/// Find the deal cell in inputs by matching its type hash to deal_cell_type_hash
fn find_deal_cell(deal_type_hash: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let mut idx = 0usize;
    loop {
        match load_cell_type_hash(idx, Source::Input) {
            Ok(Some(h)) => {
                if h.as_slice() == deal_type_hash {
                    return load_cell_data(idx, Source::Input).ok();
                }
            }
            Ok(None) => {}
            Err(_) => break,
        }
        idx += 1;
    }
    None
}

/// Find the deal cell in outputs (for active proof — deal cell is updated not consumed)
fn find_output_deal_cell(deal_type_hash: &[u8]) -> Option<alloc::vec::Vec<u8>> {
    let mut idx = 0usize;
    loop {
        match load_cell_type_hash(idx, Source::Output) {
            Ok(Some(h)) => {
                if h.as_slice() == deal_type_hash {
                    return load_cell_data(idx, Source::Output).ok();
                }
            }
            Ok(None) => {}
            Err(_) => break,
        }
        idx += 1;
    }
    None
}

fn program_entry() -> i8 {
    let script = match load_script() {
        Ok(s) => s,
        Err(_) => { debug!("escrow-lock: load_script failed"); return 1; }
    };

    let args = script.args().raw_data();
    if args.len() < ESCROW_ARGS_LEN + 1 {
        debug!("escrow-lock: args too short");
        return 1;
    }

    let deal_type_hash     = &args[0..32];
    let renter_lock_hash   = &args[32..64];
    let provider_lock_hash = &args[64..96];
    let action             = args[96];

    match action {
        // ------------------------------------------------------------------
        // PROOF_RELEASE: called by the settlement tx alongside proof-verifier
        // Release exactly price_per_epoch CKB to the provider.
        // Remaining escrow stays in a new escrow output cell.
        // ------------------------------------------------------------------
        ACTION_PROOF_RELEASE => {
            // Locate the deal cell in outputs (it's updated, not consumed)
            let deal_data = match find_output_deal_cell(deal_type_hash) {
                Some(d) => d,
                None => { debug!("escrow-lock: no output deal cell found"); return 1; }
            };
            let deal = match DealParams::from_slice(&deal_data) {
                Ok(d) => d,
                Err(_) => { debug!("escrow-lock: deal parse failed"); return 1; }
            };

            // Verify provider receives at least price_per_epoch
            if !is_lock_in_outputs(provider_lock_hash, deal.price_per_epoch()) {
                debug!("escrow-lock: provider not paid price_per_epoch");
                return 1;
            }

            // Verify a new escrow output cell exists (with the same lock)
            // The output escrow balance = input escrow - price_per_epoch - tx_fee_share
            // We don't check exact amount here; proof-verifier handles capacity math.
            // We just verify the escrow lock is preserved in an output.
            let self_script = script.calc_script_hash();
            let escrow_continues = {
                let mut idx = 0usize;
                let mut found = false;
                loop {
                    match load_cell_lock_hash(idx, Source::Output) {
                        Ok(h) => {
                            if h.as_slice() == self_script.as_slice() {
                                found = true;
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                    idx += 1;
                }
                found
            };

            if deal.state() != STATE_COMPLETE && !escrow_continues {
                debug!("escrow-lock: escrow must continue while deal is active");
                return 1;
            }
            0
        }

        // ------------------------------------------------------------------
        // REFUND: deal cancelled (pending) or expired (complete)
        // Return the remaining escrow balance to the renter.
        // ------------------------------------------------------------------
        ACTION_REFUND => {
            // Find deal cell state — must be pending or complete
            let deal_data = find_deal_cell(deal_type_hash)
                .or_else(|| find_output_deal_cell(deal_type_hash));

            let state = deal_data.as_ref()
                .and_then(|d| DealParams::from_slice(d).ok())
                .map(|d| d.state())
                .unwrap_or(STATE_COMPLETE); // If deal consumed, assume it's closed

            if state != STATE_PENDING && state != STATE_COMPLETE {
                debug!("escrow-lock: refund only allowed for pending or complete deals");
                return 1;
            }

            // Renter must receive at least the current escrow capacity
            let escrow_in_cap = load_cell_capacity(0, Source::GroupInput).unwrap_or(0);
            if !is_lock_in_outputs(renter_lock_hash, escrow_in_cap / 2) {
                // We allow partial check (minus fees); renter must get something back
                debug!("escrow-lock: renter not receiving refund output");
                return 1;
            }
            0
        }

        // ------------------------------------------------------------------
        // SLASH_REFUND: deal slashed — remaining escrow goes back to renter
        // ------------------------------------------------------------------
        ACTION_SLASH_REFUND => {
            let deal_data = find_deal_cell(deal_type_hash)
                .or_else(|| find_output_deal_cell(deal_type_hash));

            let state = deal_data.as_ref()
                .and_then(|d| DealParams::from_slice(d).ok())
                .map(|d| d.state())
                .unwrap_or(0xFF);

            if state != STATE_SLASHED {
                debug!("escrow-lock: slash refund requires deal state=slashed");
                return 1;
            }

            let escrow_in_cap = load_cell_capacity(0, Source::GroupInput).unwrap_or(0);
            if !is_lock_in_outputs(renter_lock_hash, escrow_in_cap / 2) {
                debug!("escrow-lock: renter not receiving slash refund");
                return 1;
            }
            0
        }

        _ => {
            debug!("escrow-lock: unknown action");
            1
        }
    }
}
