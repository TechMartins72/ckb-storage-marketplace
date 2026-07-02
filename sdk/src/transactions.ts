/**
 * Transaction builders for the CKB Storage Marketplace — Phase 1
 *
 * All four core deal transactions:
 *   1. createDeal    — renter creates a pending deal cell + escrow
 *   2. acceptDeal    — provider locks collateral, activates deal
 *   3. submitProof   — provider submits Merkle proof, collects epoch payment
 *   4. closeDeal     — close completed deal, release collateral to provider
 *
 * Each builder returns an unsigned CKB transaction skeleton ready for signing.
 */

import { commons, helpers, config as lumosConfig } from "@ckb-lumos/lumos";
import type { Script, OutPoint, Cell, WitnessArgs } from "@ckb-lumos/lumos";
import { bytes } from "@ckb-lumos/codec";

import {
  encodeDealParams,
  decodeDealParams,
  encodeProofSubmission,
  DEAL_PARAMS_LEN,
} from "./molecule";
import { computeChallengeIndex, type MerkleProofItem } from "./merkle";
import {
  DealState,
  DealAction,
  EscrowAction,
  CollateralAction,
  type DealParams,
  type ProtocolConfig,
  type UnsignedDealTx,
  type ProofSubmissionEncoded,
} from "./types";

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function hexPad32(hex: string): string {
  return hex.replace("0x", "").padStart(64, "0");
}

function buildDealLockScript(
  renterLockHash: string,
  providerLockHash: string,
  action: DealAction,
  cfg: ProtocolConfig,
): Script {
  const args =
    hexPad32(renterLockHash) +
    hexPad32(providerLockHash) +
    action.toString(16).padStart(2, "0");

  return {
    codeHash: cfg.scripts.dealLock.codeHash,
    hashType: cfg.scripts.dealLock.hashType,
    args: "0x" + args,
  };
}

function buildEscrowLockScript(
  dealTypeHash: string,
  renterLockHash: string,
  providerLockHash: string,
  action: EscrowAction,
  cfg: ProtocolConfig,
): Script {
  const args =
    hexPad32(dealTypeHash) +
    hexPad32(renterLockHash) +
    hexPad32(providerLockHash) +
    action.toString(16).padStart(2, "0");

  return {
    codeHash: cfg.scripts.escrowLock.codeHash,
    hashType: cfg.scripts.escrowLock.hashType,
    args: "0x" + args,
  };
}

function buildCollateralLockScript(
  dealTypeHash: string,
  providerLockHash: string,
  renterLockHash: string,
  action: CollateralAction,
  cfg: ProtocolConfig,
): Script {
  const args =
    hexPad32(dealTypeHash) +
    hexPad32(providerLockHash) +
    hexPad32(renterLockHash) +
    action.toString(16).padStart(2, "0");

  return {
    codeHash: cfg.scripts.collateralLock.codeHash,
    hashType: cfg.scripts.collateralLock.hashType,
    args: "0x" + args,
  };
}

/** Minimum CKB required to create a cell with N bytes of data (61 + N bytes, in shannons) */
function minCellCapacity(dataBytes: number): bigint {
  return BigInt(61 + dataBytes) * 100_000_000n; // 1 CKB = 1e8 shannons
}

// ---------------------------------------------------------------------------
// 1. createDeal
//    Renter creates:
//      - deal cell (pending state)
//      - escrow cell (holds full payment for all epochs)
// ---------------------------------------------------------------------------

export interface CreateDealParams {
  renterAddress: string; // CKB address (for change output)
  renterLockHash: string; // hex 32 bytes
  providerLockHash: string; // hex 32 bytes
  contentHash: string; // hex 32 bytes — SHA-256 of file
  merkleRoot: string; // hex 32 bytes — BLAKE2b Merkle root
  fileSize: bigint;
  durationEpochs: bigint;
  challengeFreq: number;
  pricePerEpoch: bigint; // shannons per epoch
}

export function buildCreateDealTx(
  params: CreateDealParams,
  cfg: ProtocolConfig,
): { dealParams: DealParams; encodedDeal: Buffer; escrowCapacity: bigint } {
  const dealParams: DealParams = {
    contentHash: params.contentHash,
    merkleRoot: params.merkleRoot,
    fileSize: params.fileSize,
    dealDuration: params.durationEpochs,
    challengeFreq: params.challengeFreq,
    pricePerEpoch: params.pricePerEpoch,
    renterLockHash: params.renterLockHash,
    providerLockHash: params.providerLockHash,
    startEpoch: 0n,
    lastProofEpoch: 0n,
    state: DealState.Pending,
  };

  const encodedDeal = encodeDealParams(dealParams);

  // Escrow holds full payment: price_per_epoch * deal_duration
  const totalPayment = params.pricePerEpoch * params.durationEpochs;
  const escrowCapacity = minCellCapacity(DEAL_PARAMS_LEN) + totalPayment;

  return { dealParams, encodedDeal, escrowCapacity };
}

// ---------------------------------------------------------------------------
// 2. acceptDeal
//    Provider accepts pending deal:
//      - consumes pending deal cell
//      - outputs active deal cell (sets start_epoch)
//      - outputs collateral cell (provider locks 2x total payment)
// ---------------------------------------------------------------------------

export interface AcceptDealParams {
  dealOutpoint: OutPoint;
  dealCell: Cell; // the pending deal cell
  providerAddress: string;
  providerLockHash: string;
  renterLockHash: string;
  currentEpoch: bigint;
  collateralMultiplier: number; // default 2
}

export interface AcceptDealResult {
  activeDealData: Buffer;
  collateralCapacity: bigint;
  dealTypeHash: string;
}

export function buildAcceptDealResult(
  params: AcceptDealParams,
  cfg: ProtocolConfig,
): AcceptDealResult {
  const existingData = Buffer.from(
    params.dealCell.data.replace("0x", ""),
    "hex",
  );
  const deal = decodeDealParams(existingData);

  // Update to active state
  const activeDeal: DealParams = {
    ...deal,
    state: DealState.Active,
    startEpoch: params.currentEpoch,
    lastProofEpoch: params.currentEpoch,
  };

  const activeDealData = encodeDealParams(activeDeal);

  // Collateral = collateralMultiplier * total_payment
  const totalPayment = deal.pricePerEpoch * deal.dealDuration;
  const collateral = totalPayment * BigInt(params.collateralMultiplier);
  const collateralCapacity = minCellCapacity(DEAL_PARAMS_LEN) + collateral;

  // The deal type hash is derived from the deal cell's type script
  // In practice this comes from the CKB node after the createDeal tx confirms
  const dealTypeHash = params.dealCell.cellOutput.type
    ? helpers.computeScriptHash(params.dealCell.cellOutput.type)
    : "0x" + "00".repeat(32);

  return {
    activeDealData,
    collateralCapacity,
    dealTypeHash,
  };
}

// ---------------------------------------------------------------------------
// 3. submitProof
//    Provider submits a Merkle proof in response to a challenge:
//      - consumes deal cell + escrow cell
//      - outputs: updated deal cell, provider payment, remaining escrow
//    The proof-verifier type script runs and validates everything on-chain.
// ---------------------------------------------------------------------------

export interface SubmitProofParams {
  dealOutpoint: OutPoint;
  dealCell: Cell;
  escrowCell: Cell;
  challengeEpoch: bigint;
  blockHash: string; // block hash from the challenge epoch header
  leafDataHash: string; // BLAKE2b of the challenged chunk (hex)
  merklePath: MerkleProofItem[];
}

export interface SubmitProofWitness {
  proofBytes: Buffer;
  challengeIndex: number;
  updatedDealData: Buffer;
}

export function buildSubmitProofWitness(
  params: SubmitProofParams,
): SubmitProofWitness {
  const dealData = Buffer.from(params.dealCell.data.replace("0x", ""), "hex");
  const deal = decodeDealParams(dealData);

  const numChunks = Number(
    (deal.fileSize + BigInt(256 * 1024) - 1n) / BigInt(256 * 1024),
  );
  const challengeIndex = computeChallengeIndex(
    params.blockHash,
    params.dealOutpoint.txHash,
    numChunks,
  );

  const proofEncoded: ProofSubmissionEncoded = {
    dealTxHash: params.dealOutpoint.txHash,
    dealIndex: parseInt(params.dealOutpoint.index, 16),
    challengeEpoch: params.challengeEpoch,
    challengeIndex: BigInt(challengeIndex),
    leafDataHash: params.leafDataHash,
    merklePath: params.merklePath,
  };

  const proofBytes = encodeProofSubmission(proofEncoded);

  // Determine new deal state after this proof
  const endEpoch = deal.startEpoch + deal.dealDuration;
  const newState =
    params.challengeEpoch >= endEpoch ? DealState.Complete : DealState.Active;

  const updatedDeal: DealParams = {
    ...deal,
    lastProofEpoch: params.challengeEpoch,
    state: newState,
  };

  return {
    proofBytes,
    challengeIndex,
    updatedDealData: encodeDealParams(updatedDeal),
  };
}

// ---------------------------------------------------------------------------
// 4. closeDeal
//    Close a completed deal; release provider collateral.
//    Either party can sign.
// ---------------------------------------------------------------------------

export interface CloseDealParams {
  dealOutpoint: OutPoint;
  dealCell: Cell;
  collateralCell: Cell;
  dealTypeHash: string;
  providerLockHash: string;
  renterLockHash: string;
}

export interface CloseDealResult {
  /** Capacity the provider will receive (collateral + any residual) */
  providerReceives: bigint;
  /** Updated deal data bytes with state = complete */
  closedDealData: Buffer | null; // null if deal cell is consumed not updated
}

export function buildCloseDealResult(params: CloseDealParams): CloseDealResult {
  const dealData = Buffer.from(params.dealCell.data.replace("0x", ""), "hex");
  const deal = decodeDealParams(dealData);

  if (deal.state !== DealState.Complete) {
    throw new Error(
      `closeDeal: deal state must be Complete, got ${deal.state}`,
    );
  }

  // In the close transaction, the collateral cell is consumed and the full
  // collateral amount goes back to the provider (minus tx fee).
  const collateralCap = BigInt(params.collateralCell.cellOutput.capacity);
  const txFee = 1_000_000n; // 0.01 CKB estimate

  return {
    providerReceives: collateralCap - txFee,
    closedDealData: null, // deal cell is consumed in close
  };
}

// ---------------------------------------------------------------------------
// Exported convenience object
// ---------------------------------------------------------------------------
export const TxBuilders = {
  createDeal: buildCreateDealTx,
  acceptDeal: buildAcceptDealResult,
  submitProof: buildSubmitProofWitness,
  closeDeal: buildCloseDealResult,
};
