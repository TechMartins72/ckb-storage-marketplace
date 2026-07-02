/**
 * Core TypeScript types for the CKB Storage Marketplace
 */

import type { Script, OutPoint, Transaction } from "@ckb-lumos/lumos";

// ---------------------------------------------------------------------------
// Deal state enum (mirrors on-chain u8)
// ---------------------------------------------------------------------------
export enum DealState {
  Pending  = 0,
  Active   = 1,
  Complete = 2,
  Slashed  = 3,
}

// ---------------------------------------------------------------------------
// Deal action enum (stored in lock script args[64])
// ---------------------------------------------------------------------------
export enum DealAction {
  Cancel = 0,
  Accept = 1,
  Proof  = 2,
  Close  = 3,
  Slash  = 4,
}

// ---------------------------------------------------------------------------
// Escrow action enum (stored in escrow lock script args[96])
// ---------------------------------------------------------------------------
export enum EscrowAction {
  ProofRelease = 0,
  Refund       = 1,
  SlashRefund  = 2,
}

// ---------------------------------------------------------------------------
// Collateral action enum
// ---------------------------------------------------------------------------
export enum CollateralAction {
  Release = 0,
  Slash   = 1,
}

// ---------------------------------------------------------------------------
// DealParams — mirrors the on-chain molecule struct
// ---------------------------------------------------------------------------
export interface DealParams {
  contentHash:     string; // hex, 32 bytes — SHA-256 of full file
  merkleRoot:      string; // hex, 32 bytes — BLAKE2b Merkle root
  fileSize:        bigint; // bytes
  dealDuration:    bigint; // CKB epochs
  challengeFreq:   number; // epochs between required proofs
  pricePerEpoch:   bigint; // shannons
  renterLockHash:  string; // hex, 32 bytes
  providerLockHash:string; // hex, 32 bytes
  startEpoch:      bigint;
  lastProofEpoch:  bigint;
  state:           DealState;
}

// ---------------------------------------------------------------------------
// Deployed script references (outpoints on testnet/mainnet)
// ---------------------------------------------------------------------------
export interface ScriptDeployment {
  codeHash: string;   // hex, 32 bytes
  hashType: "data" | "data1" | "type";
  outPoint: OutPoint;
}

export interface ProtocolConfig {
  ckbNodeUrl:       string;
  ckbIndexerUrl:    string;
  marketplaceApiUrl:string;
  scripts: {
    dealLock:        ScriptDeployment;
    escrowLock:      ScriptDeployment;
    collateralLock:  ScriptDeployment;
    proofVerifier:   ScriptDeployment;
  };
  collateralMultiplier: number; // default: 2 (2x deal total)
}

// ---------------------------------------------------------------------------
// Upload session — tracks chunked file upload to a provider
// ---------------------------------------------------------------------------
export interface UploadSession {
  sessionId:       string;
  providerUrl:     string;
  totalChunks:     number;
  uploadedChunks:  number;
  merkleRoot?:     string;
  contentHash?:    string;
}

// ---------------------------------------------------------------------------
// Deal status as returned by the marketplace API / indexer
// ---------------------------------------------------------------------------
export interface DealStatus {
  dealOutpoint:     OutPoint;
  params:           DealParams;
  proofHistory:     ProofRecord[];
  nextChallengeEpoch: bigint | null;
  escrowBalance:    bigint; // shannons remaining
}

export interface ProofRecord {
  epoch:       bigint;
  txHash:      string;
  valid:       boolean;
  submittedAt: Date;
}

// ---------------------------------------------------------------------------
// Transaction builder result — unsigned tx for the user/signer
// ---------------------------------------------------------------------------
export interface UnsignedDealTx {
  transaction:  Transaction;
  signingEntries: SigningEntry[];
}

export interface SigningEntry {
  type:    "witness_args_lock";
  index:   number;
  message: string; // hex digest to sign
}

// ---------------------------------------------------------------------------
// Provider info from the registry
// ---------------------------------------------------------------------------
export interface ProviderInfo {
  lockHash:       string;
  endpointUrl:    string;
  reputationScore:number;
  totalDeals:     number;
  slashCount:     number;
  pricePerGbEpoch:bigint; // shannons
  availableBytes:  bigint;
}

// ---------------------------------------------------------------------------
// Chunk info
// ---------------------------------------------------------------------------
export const CHUNK_SIZE_BYTES = 256 * 1024; // 256 KB

export function numChunks(fileSize: bigint): number {
  return Number((fileSize + BigInt(CHUNK_SIZE_BYTES) - 1n) / BigInt(CHUNK_SIZE_BYTES));
}
