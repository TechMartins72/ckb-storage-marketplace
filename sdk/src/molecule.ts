/**
 * Molecule codec helpers for DealParams and ProofSubmission.
 *
 * These encode/decode the fixed-layout byte structures that map 1:1
 * to the Rust types in contracts/generated/types.rs.
 */

import type { DealParams } from "./types";
import { DealState } from "./types";
import type { MerkleProofItem } from "./merkle";

// ---------------------------------------------------------------------------
// Layout constants (must stay in sync with types.rs)
// ---------------------------------------------------------------------------
export const DEAL_PARAMS_LEN   = 173;
const OFF_CONTENT_HASH         = 0;
const OFF_MERKLE_ROOT          = 32;
const OFF_FILE_SIZE            = 64;
const OFF_DEAL_DURATION        = 72;
const OFF_CHALLENGE_FREQ       = 80;
const OFF_PRICE_PER_EPOCH      = 84;
const OFF_RENTER_LOCK_HASH     = 92;
const OFF_PROVIDER_LOCK_HASH   = 124;
const OFF_START_EPOCH          = 156;
const OFF_LAST_PROOF_EPOCH     = 164;
const OFF_STATE                = 172;

// ---------------------------------------------------------------------------
// Encode DealParams to bytes
// ---------------------------------------------------------------------------
export function encodeDealParams(p: DealParams): Buffer {
  const buf = Buffer.alloc(DEAL_PARAMS_LEN, 0);

  hexToBytes(p.contentHash).copy(buf, OFF_CONTENT_HASH);
  hexToBytes(p.merkleRoot).copy(buf, OFF_MERKLE_ROOT);
  writeBigUInt64LE(buf, p.fileSize,       OFF_FILE_SIZE);
  writeBigUInt64LE(buf, p.dealDuration,   OFF_DEAL_DURATION);
  buf.writeUInt32LE(p.challengeFreq,      OFF_CHALLENGE_FREQ);
  writeBigUInt64LE(buf, p.pricePerEpoch,  OFF_PRICE_PER_EPOCH);
  hexToBytes(p.renterLockHash).copy(buf,  OFF_RENTER_LOCK_HASH);
  hexToBytes(p.providerLockHash).copy(buf,OFF_PROVIDER_LOCK_HASH);
  writeBigUInt64LE(buf, p.startEpoch,     OFF_START_EPOCH);
  writeBigUInt64LE(buf, p.lastProofEpoch, OFF_LAST_PROOF_EPOCH);
  buf[OFF_STATE] = p.state;

  return buf;
}

// ---------------------------------------------------------------------------
// Decode DealParams from bytes
// ---------------------------------------------------------------------------
export function decodeDealParams(buf: Buffer): DealParams {
  if (buf.length < DEAL_PARAMS_LEN) {
    throw new Error(`DealParams: buffer too short (${buf.length} < ${DEAL_PARAMS_LEN})`);
  }

  return {
    contentHash:      "0x" + buf.slice(OFF_CONTENT_HASH,       OFF_CONTENT_HASH + 32).toString("hex"),
    merkleRoot:       "0x" + buf.slice(OFF_MERKLE_ROOT,        OFF_MERKLE_ROOT + 32).toString("hex"),
    fileSize:         readBigUInt64LE(buf, OFF_FILE_SIZE),
    dealDuration:     readBigUInt64LE(buf, OFF_DEAL_DURATION),
    challengeFreq:    buf.readUInt32LE(OFF_CHALLENGE_FREQ),
    pricePerEpoch:    readBigUInt64LE(buf, OFF_PRICE_PER_EPOCH),
    renterLockHash:   "0x" + buf.slice(OFF_RENTER_LOCK_HASH,   OFF_RENTER_LOCK_HASH + 32).toString("hex"),
    providerLockHash: "0x" + buf.slice(OFF_PROVIDER_LOCK_HASH, OFF_PROVIDER_LOCK_HASH + 32).toString("hex"),
    startEpoch:       readBigUInt64LE(buf, OFF_START_EPOCH),
    lastProofEpoch:   readBigUInt64LE(buf, OFF_LAST_PROOF_EPOCH),
    state:            buf[OFF_STATE] as DealState,
  };
}

// ---------------------------------------------------------------------------
// Encode ProofSubmission for the transaction witness
// Layout matches types.rs PROOF_HEADER_LEN + path items
// ---------------------------------------------------------------------------
export interface ProofSubmissionEncoded {
  dealTxHash:     string; // hex
  dealIndex:      number;
  challengeEpoch: bigint;
  challengeIndex: bigint;
  leafDataHash:   string; // hex — BLAKE2b of the challenged chunk
  merklePath:     MerkleProofItem[];
}

export function encodeProofSubmission(p: ProofSubmissionEncoded): Buffer {
  const HEADER_LEN = 88;
  const ITEM_LEN   = 33;
  const total = HEADER_LEN + p.merklePath.length * ITEM_LEN;
  const buf = Buffer.alloc(total, 0);

  hexToBytes(p.dealTxHash).copy(buf, 0);
  buf.writeUInt32LE(p.dealIndex,          32);
  writeBigUInt64LE(buf, p.challengeEpoch, 36);
  writeBigUInt64LE(buf, p.challengeIndex, 44);
  hexToBytes(p.leafDataHash).copy(buf,    52);
  buf.writeUInt32LE(p.merklePath.length,  84);

  let offset = HEADER_LEN;
  for (const { siblingHash, isLeft } of p.merklePath) {
    siblingHash.copy(buf, offset);
    buf[offset + 32] = isLeft ? 1 : 0;
    offset += ITEM_LEN;
  }

  return buf;
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Buffer {
  return Buffer.from(hex.replace("0x", ""), "hex");
}

function writeBigUInt64LE(buf: Buffer, value: bigint, offset: number): void {
  const lo = Number(value & 0xFFFF_FFFFn);
  const hi = Number((value >> 32n) & 0xFFFF_FFFFn);
  buf.writeUInt32LE(lo, offset);
  buf.writeUInt32LE(hi, offset + 4);
}

function readBigUInt64LE(buf: Buffer, offset: number): bigint {
  const lo = BigInt(buf.readUInt32LE(offset));
  const hi = BigInt(buf.readUInt32LE(offset + 4));
  return lo + (hi << 32n);
}
