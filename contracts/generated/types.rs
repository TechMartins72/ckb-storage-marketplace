// Auto-generated molecule bindings (hand-authored equivalent).
// In a real build, these come from: moleculec --language rust --schema-file schemas/deal.mol
// and are included via: include!(concat!(env!("OUT_DIR"), "/types.rs"))
//
// For development, this file is included directly.

use core::convert::TryInto;

// ---------------------------------------------------------------------------
// Primitive helpers
// ---------------------------------------------------------------------------

pub fn u8_from_slice(s: &[u8]) -> u8 {
    s[0]
}

pub fn u32_from_le(s: &[u8]) -> u32 {
    u32::from_le_bytes(s[0..4].try_into().unwrap())
}

pub fn u64_from_le(s: &[u8]) -> u64 {
    u64::from_le_bytes(s[0..8].try_into().unwrap())
}

pub fn u32_to_le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

pub fn u64_to_le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

// ---------------------------------------------------------------------------
// DealState constants
// ---------------------------------------------------------------------------

pub const STATE_PENDING:   u8 = 0;
pub const STATE_ACTIVE:    u8 = 1;
pub const STATE_COMPLETE:  u8 = 2;
pub const STATE_SLASHED:   u8 = 3;

// ---------------------------------------------------------------------------
// DealParams — fixed-layout offsets for direct byte parsing
//
// Layout (all little-endian):
//   [0..32]   content_hash
//   [32..64]  merkle_root
//   [64..72]  file_size
//   [72..80]  deal_duration
//   [80..84]  challenge_freq
//   [84..92]  price_per_epoch
//   [92..124] renter_lock_hash  (32-byte hash of renter lock script)
//   [124..156] provider_lock_hash (32-byte hash of provider lock script)
//   [156..164] start_epoch
//   [164..172] last_proof_epoch
//   [172]      state
//   Total: 173 bytes
// ---------------------------------------------------------------------------

pub const DEAL_PARAMS_LEN: usize = 173;

pub const OFF_CONTENT_HASH:        usize = 0;
pub const OFF_MERKLE_ROOT:         usize = 32;
pub const OFF_FILE_SIZE:           usize = 64;
pub const OFF_DEAL_DURATION:       usize = 72;
pub const OFF_CHALLENGE_FREQ:      usize = 80;
pub const OFF_PRICE_PER_EPOCH:     usize = 84;
pub const OFF_RENTER_LOCK_HASH:    usize = 92;
pub const OFF_PROVIDER_LOCK_HASH:  usize = 124;
pub const OFF_START_EPOCH:         usize = 156;
pub const OFF_LAST_PROOF_EPOCH:    usize = 164;
pub const OFF_STATE:               usize = 172;

pub struct DealParams<'a> {
    raw: &'a [u8],
}

impl<'a> DealParams<'a> {
    pub fn from_slice(raw: &'a [u8]) -> Result<Self, &'static str> {
        if raw.len() < DEAL_PARAMS_LEN {
            return Err("DealParams: data too short");
        }
        Ok(Self { raw })
    }

    pub fn content_hash(&self)       -> &[u8] { &self.raw[OFF_CONTENT_HASH..OFF_CONTENT_HASH + 32] }
    pub fn merkle_root(&self)        -> &[u8] { &self.raw[OFF_MERKLE_ROOT..OFF_MERKLE_ROOT + 32] }
    pub fn file_size(&self)          -> u64   { u64_from_le(&self.raw[OFF_FILE_SIZE..]) }
    pub fn deal_duration(&self)      -> u64   { u64_from_le(&self.raw[OFF_DEAL_DURATION..]) }
    pub fn challenge_freq(&self)     -> u32   { u32_from_le(&self.raw[OFF_CHALLENGE_FREQ..]) }
    pub fn price_per_epoch(&self)    -> u64   { u64_from_le(&self.raw[OFF_PRICE_PER_EPOCH..]) }
    pub fn renter_lock_hash(&self)   -> &[u8] { &self.raw[OFF_RENTER_LOCK_HASH..OFF_RENTER_LOCK_HASH + 32] }
    pub fn provider_lock_hash(&self) -> &[u8] { &self.raw[OFF_PROVIDER_LOCK_HASH..OFF_PROVIDER_LOCK_HASH + 32] }
    pub fn start_epoch(&self)        -> u64   { u64_from_le(&self.raw[OFF_START_EPOCH..]) }
    pub fn last_proof_epoch(&self)   -> u64   { u64_from_le(&self.raw[OFF_LAST_PROOF_EPOCH..]) }
    pub fn state(&self)              -> u8    { u8_from_slice(&self.raw[OFF_STATE..]) }

    /// Number of 256KB chunks (ceiling division)
    pub fn num_chunks(&self) -> u64 {
        let chunk_size: u64 = 256 * 1024;
        (self.file_size() + chunk_size - 1) / chunk_size
    }
}

/// Mutable builder for writing updated DealParams back to a byte buffer
pub struct DealParamsMut {
    pub buf: [u8; DEAL_PARAMS_LEN],
}

impl DealParamsMut {
    pub fn from_slice(src: &[u8]) -> Result<Self, &'static str> {
        if src.len() < DEAL_PARAMS_LEN {
            return Err("DealParamsMut: source too short");
        }
        let mut buf = [0u8; DEAL_PARAMS_LEN];
        buf.copy_from_slice(&src[..DEAL_PARAMS_LEN]);
        Ok(Self { buf })
    }

    pub fn set_state(&mut self, state: u8) {
        self.buf[OFF_STATE] = state;
    }

    pub fn set_start_epoch(&mut self, epoch: u64) {
        self.buf[OFF_START_EPOCH..OFF_START_EPOCH + 8].copy_from_slice(&u64_to_le(epoch));
    }

    pub fn set_last_proof_epoch(&mut self, epoch: u64) {
        self.buf[OFF_LAST_PROOF_EPOCH..OFF_LAST_PROOF_EPOCH + 8].copy_from_slice(&u64_to_le(epoch));
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

// ---------------------------------------------------------------------------
// ProofSubmission — parsed from transaction witness
//
// Byte layout (variable length):
//   [0..32]   deal_outpoint_tx_hash
//   [32..36]  deal_outpoint_index  (u32 LE)
//   [36..44]  challenge_epoch      (u64 LE)
//   [44..52]  challenge_index      (u64 LE)
//   [52..84]  leaf_data_hash
//   [84..88]  path_len             (u32 LE, number of MerklePathItems)
//   [88..]    merkle_path items:   each item = 32 bytes sibling + 1 byte is_left = 33 bytes
// ---------------------------------------------------------------------------

pub const PROOF_HEADER_LEN:  usize = 88;
pub const MERKLE_ITEM_LEN:   usize = 33;

pub struct MerklePathItem {
    pub sibling_hash: [u8; 32],
    pub is_left:      bool,
}

pub struct ProofSubmission {
    pub deal_tx_hash:     [u8; 32],
    pub deal_index:       u32,
    pub challenge_epoch:  u64,
    pub challenge_index:  u64,
    pub leaf_data_hash:   [u8; 32],
    pub merkle_path:      alloc::vec::Vec<MerklePathItem>,
}

impl ProofSubmission {
    pub fn from_slice(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < PROOF_HEADER_LEN {
            return Err("ProofSubmission: witness too short");
        }

        let mut deal_tx_hash = [0u8; 32];
        deal_tx_hash.copy_from_slice(&raw[0..32]);

        let deal_index = u32_from_le(&raw[32..36]);
        let challenge_epoch = u64_from_le(&raw[36..44]);
        let challenge_index = u64_from_le(&raw[44..52]);

        let mut leaf_data_hash = [0u8; 32];
        leaf_data_hash.copy_from_slice(&raw[52..84]);

        let path_len = u32_from_le(&raw[84..88]) as usize;
        let expected_total = PROOF_HEADER_LEN + path_len * MERKLE_ITEM_LEN;
        if raw.len() < expected_total {
            return Err("ProofSubmission: witness truncated in merkle path");
        }

        let mut merkle_path = alloc::vec::Vec::with_capacity(path_len);
        let mut offset = PROOF_HEADER_LEN;
        for _ in 0..path_len {
            let mut sibling_hash = [0u8; 32];
            sibling_hash.copy_from_slice(&raw[offset..offset + 32]);
            let is_left = raw[offset + 32] != 0;
            merkle_path.push(MerklePathItem { sibling_hash, is_left });
            offset += MERKLE_ITEM_LEN;
        }

        Ok(Self {
            deal_tx_hash,
            deal_index,
            challenge_epoch,
            challenge_index,
            leaf_data_hash,
            merkle_path,
        })
    }
}
