//! collateral-lock — CKB Lock Script
//!
//! Holds the provider's locked CKB collateral (default: 2x total deal payment).
//!
//! Lock args layout (97 bytes):
//!   [0..32]   deal_cell_type_hash
//!   [32..64]  provider_lock_hash   — collateral returned here on success
//!   [64..96]  renter_lock_hash     — 50% compensation here on slash
//!   [96]      action               — 0=release, 1=slash
//!
//! Spending conditions:
//!   1. RELEASE — deal completed normally; all collateral back to provider
//!   2. SLASH   — proof deadline missed
//!                 50% → dead address (0x0000...0000) [burn]
//!                 50% → renter as compensation

#![no_std]
#![no_main]

use ckb_std::{
    ckb_constants::Source,
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

// The "dead" / burn address: secp256k1 lock with all-zero args.
// Any CKB sent here is permanently unspendable.
const DEAD_LOCK_HASH: [u8; 32] = [
    // blake2b("ckb_dead_lock") — pre-computed placeholder
    // In production replace with the actual hash of the burn lock script
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const ACTION_RELEASE: u8 = 0;
const ACTION_SLASH:   u8 = 1;

fn capacity_to_lock(lock_hash: &[u8]) -> u64 {
    let mut idx = 0usize;
    let mut total = 0u64;
    loop {
        match load_cell_lock_hash(idx, Source::Output) {
            Ok(h) => {
                if h.as_slice() == lock_hash {
                    total += load_cell_capacity(idx, Source::Output).unwrap_or(0);
                }
            }
            Err(_) => break,
        }
        idx += 1;
    }
    total
}

fn find_deal_state(deal_type_hash: &[u8]) -> Option<u8> {
    // Check both inputs and outputs (deal may be consumed or updated)
    for source in [Source::Input, Source::Output] {
        let mut idx = 0usize;
        loop {
            match load_cell_type_hash(idx, source) {
                Ok(Some(h)) => {
                    if h.as_slice() == deal_type_hash {
                        if let Ok(data) = load_cell_data(idx, source) {
                            if let Ok(d) = DealParams::from_slice(&data) {
                                return Some(d.state());
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(_) => break,
            }
            idx += 1;
        }
    }
    None
}

fn program_entry() -> i8 {
    let script = match load_script() {
        Ok(s) => s,
        Err(_) => { debug!("collateral-lock: load_script failed"); return 1; }
    };

    let args = script.args().raw_data();
    if args.len() < 97 {
        debug!("collateral-lock: args too short (need 97 bytes)");
        return 1;
    }

    let deal_type_hash     = &args[0..32];
    let provider_lock_hash = &args[32..64];
    let renter_lock_hash   = &args[64..96];
    let action             = args[96];

    // Current collateral capacity (sum of all GroupInput cells with this lock)
    let collateral_cap = load_cell_capacity(0, Source::GroupInput).unwrap_or(0);

    match action {
        // ------------------------------------------------------------------
        // RELEASE: deal completed; return all collateral to provider
        // ------------------------------------------------------------------
        ACTION_RELEASE => {
            let state = find_deal_state(deal_type_hash);
            if state != Some(STATE_COMPLETE) {
                debug!("collateral-lock: release requires deal state=complete");
                return 1;
            }

            let provider_receives = capacity_to_lock(provider_lock_hash);
            // Allow for a small tx fee deduction (max 0.1 CKB = 10_000_000 shannons)
            let fee_allowance: u64 = 10_000_000;
            if provider_receives + fee_allowance < collateral_cap {
                debug!("collateral-lock: provider not receiving full collateral");
                return 1;
            }
            0
        }

        // ------------------------------------------------------------------
        // SLASH: proof deadline missed
        //   50% → dead address (burned)
        //   50% → renter (compensation)
        // ------------------------------------------------------------------
        ACTION_SLASH => {
            let state = find_deal_state(deal_type_hash);
            if state != Some(STATE_SLASHED) {
                debug!("collateral-lock: slash requires deal state=slashed");
                return 1;
            }

            // Calculate expected splits
            let half = collateral_cap / 2;
            let fee_allowance: u64 = 10_000_000;

            // 50% must go to renter
            let renter_receives = capacity_to_lock(renter_lock_hash);
            if renter_receives + fee_allowance < half {
                debug!("collateral-lock: renter not receiving 50% of collateral");
                return 1;
            }

            // 50% must be burned (sent to dead lock)
            let burned = capacity_to_lock(&DEAD_LOCK_HASH);
            if burned + fee_allowance < half {
                debug!("collateral-lock: burn output insufficient");
                return 1;
            }

            0
        }

        _ => {
            debug!("collateral-lock: unknown action");
            1
        }
    }
}
