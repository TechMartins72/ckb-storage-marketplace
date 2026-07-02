/**
 * ckb-storage-sdk — main exports
 */

export * from "./types";
export * from "./merkle";
export * from "./molecule";
export * from "./transactions";

// ---------------------------------------------------------------------------
// RenterClient — high-level interface for renters
// ---------------------------------------------------------------------------

import { createHash } from "crypto";
import { splitIntoChunks, MerkleTree, computeChallengeIndex } from "./merkle";
import { encodeDealParams, decodeDealParams } from "./molecule";
import { buildCreateDealTx } from "./transactions";
import {
  DealState, CHUNK_SIZE_BYTES, numChunks,
  type ProtocolConfig, type DealParams, type DealStatus, type UploadSession,
} from "./types";
import type { OutPoint } from "@ckb-lumos/lumos";

export interface RenterClientConfig {
  config: ProtocolConfig;
  renterAddress:  string;
  renterLockHash: string;
}

export class RenterClient {
  private readonly cfg: ProtocolConfig;
  private readonly address: string;
  private readonly lockHash: string;

  constructor(opts: RenterClientConfig) {
    this.cfg      = opts.config;
    this.address  = opts.renterAddress;
    this.lockHash = opts.renterLockHash;
  }

  /**
   * Prepare a file for upload:
   *   1. Split into 256 KB chunks
   *   2. Build Merkle tree
   *   3. Compute content hash (SHA-256 of full file)
   *   Returns merkleRoot and contentHash — both needed for createDeal
   */
  prepareFile(fileData: Uint8Array): {
    chunks:      Uint8Array[];
    tree:        MerkleTree;
    merkleRoot:  string;
    contentHash: string;
  } {
    const chunks = splitIntoChunks(fileData);
    const tree   = new MerkleTree(chunks);

    const contentHash = "0x" + createHash("sha256").update(fileData).digest("hex");

    return {
      chunks,
      tree,
      merkleRoot:  tree.getRootHex(),
      contentHash,
    };
  }

  /**
   * Build the deal parameters for createDeal transaction.
   * The caller must obtain providerLockHash from the provider registry API first.
   */
  buildDeal(opts: {
    merkleRoot:      string;
    contentHash:     string;
    fileSize:        bigint;
    durationEpochs:  bigint;
    challengeFreq:   number;
    pricePerEpoch:   bigint;
    providerLockHash:string;
  }) {
    return buildCreateDealTx(
      {
        renterAddress:    this.address,
        renterLockHash:   this.lockHash,
        providerLockHash: opts.providerLockHash,
        contentHash:      opts.contentHash,
        merkleRoot:       opts.merkleRoot,
        fileSize:         opts.fileSize,
        durationEpochs:   opts.durationEpochs,
        challengeFreq:    opts.challengeFreq,
        pricePerEpoch:    opts.pricePerEpoch,
      },
      this.cfg,
    );
  }

  /**
   * Estimate total cost for a deal.
   */
  estimateCost(pricePerEpoch: bigint, durationEpochs: bigint): {
    totalPayment:     bigint;
    collateralNeeded: bigint; // provider's burden, not renter's
    escrowRequired:   bigint;
  } {
    const totalPayment   = pricePerEpoch * durationEpochs;
    const collateralNeeded = totalPayment * BigInt(this.cfg.collateralMultiplier);
    const DEAL_CELL_OVERHEAD = 173n * 100_000_000n;
    const escrowRequired = DEAL_CELL_OVERHEAD + totalPayment;

    return { totalPayment, collateralNeeded, escrowRequired };
  }
}

// ---------------------------------------------------------------------------
// ProviderClient — high-level interface for providers
// ---------------------------------------------------------------------------

import { buildAcceptDealResult, buildSubmitProofWitness, buildCloseDealResult } from "./transactions";
import type { Cell } from "@ckb-lumos/lumos";
import type { MerkleProofItem } from "./merkle";

export interface ProviderClientConfig {
  config:           ProtocolConfig;
  providerAddress:  string;
  providerLockHash: string;
}

export class ProviderClient {
  private readonly cfg:      ProtocolConfig;
  private readonly address:  string;
  private readonly lockHash: string;

  constructor(opts: ProviderClientConfig) {
    this.cfg      = opts.config;
    this.address  = opts.providerAddress;
    this.lockHash = opts.providerLockHash;
  }

  /**
   * Prepare the data for an acceptDeal transaction.
   */
  prepareAccept(opts: {
    dealOutpoint:  OutPoint;
    dealCell:      Cell;
    renterLockHash:string;
    currentEpoch:  bigint;
  }) {
    return buildAcceptDealResult(
      {
        dealOutpoint:         opts.dealOutpoint,
        dealCell:             opts.dealCell,
        providerAddress:      this.address,
        providerLockHash:     this.lockHash,
        renterLockHash:       opts.renterLockHash,
        currentEpoch:         opts.currentEpoch,
        collateralMultiplier: this.cfg.collateralMultiplier,
      },
      this.cfg,
    );
  }

  /**
   * Build the proof witness for a submitProof transaction.
   * The MerkleTree must be built from the stored file chunks.
   */
  prepareProof(opts: {
    dealOutpoint:  OutPoint;
    dealCell:      Cell;
    escrowCell:    Cell;
    challengeEpoch:bigint;
    blockHash:     string;
    tree:          MerkleTree;
  }) {
    // Compute challenge index
    const dealData = Buffer.from(opts.dealCell.data.replace("0x", ""), "hex");
    const deal = decodeDealParams(dealData);
    const chunks = numChunks(deal.fileSize);
    const challengeIndex = computeChallengeIndex(
      opts.blockHash,
      opts.dealOutpoint.txHash,
      chunks,
    );

    const leafHash    = opts.tree.leaves[challengeIndex];
    const merklePath  = opts.tree.getProof(challengeIndex);

    return buildSubmitProofWitness({
      dealOutpoint:   opts.dealOutpoint,
      dealCell:       opts.dealCell,
      escrowCell:     opts.escrowCell,
      challengeEpoch: opts.challengeEpoch,
      blockHash:      opts.blockHash,
      leafDataHash:   "0x" + leafHash.toString("hex"),
      merklePath,
    });
  }

  /**
   * Prepare a closeDeal transaction.
   */
  prepareClose(opts: {
    dealOutpoint:   OutPoint;
    dealCell:       Cell;
    collateralCell: Cell;
    dealTypeHash:   string;
    renterLockHash: string;
  }) {
    return buildCloseDealResult({
      dealOutpoint:      opts.dealOutpoint,
      dealCell:          opts.dealCell,
      collateralCell:    opts.collateralCell,
      dealTypeHash:      opts.dealTypeHash,
      providerLockHash:  this.lockHash,
      renterLockHash:    opts.renterLockHash,
    });
  }
}
