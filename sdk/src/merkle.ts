/**
 * Merkle tree for Proof-of-Data-Possession (PDP)
 *
 * Uses BLAKE2b-256 (matching the on-chain proof-verifier script).
 * The tree is a standard binary Merkle tree with sibling-pair ordering:
 *   - If leaf index is even, it pairs with index+1 (right sibling)
 *   - If leaf index is odd, it pairs with index-1 (left sibling)
 */

import { blake2b } from "@nervosnetwork/ckb-sdk-utils";
import { CHUNK_SIZE_BYTES } from "./types";

// ---------------------------------------------------------------------------
// Hash a single chunk using BLAKE2b-256
// ---------------------------------------------------------------------------
export function hashChunk(chunk: Uint8Array): Buffer {
  return Buffer.from(
    blake2b(32, null, null, Buffer.from("ckb-default-hash"))(chunk),
  );
}

// ---------------------------------------------------------------------------
// Build a binary Merkle tree from an array of leaf hashes.
// Returns a 2D array where tree[0] = leaves, tree[last] = [root].
// ---------------------------------------------------------------------------
export function buildMerkleTree(leaves: Buffer[]): Buffer[][] {
  if (leaves.length === 0)
    throw new Error("Cannot build Merkle tree from empty leaves");

  const tree: Buffer[][] = [leaves.slice()];
  let level = leaves.slice();

  while (level.length > 1) {
    const nextLevel: Buffer[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : level[i]; // duplicate last if odd
      const combined = Buffer.concat([left, right]);
      nextLevel.push(
        Buffer.from(
          blake2b(32, null, null, Buffer.from("ckb-default-hash"))(combined),
        ),
      );
    }
    tree.push(nextLevel);
    level = nextLevel;
  }

  return tree;
}

export interface MerkleProofItem {
  siblingHash: Buffer;
  isLeft: boolean; // true = sibling is on the left
}

// ---------------------------------------------------------------------------
// Compute Merkle proof path for a given leaf index
// ---------------------------------------------------------------------------
export function getMerkleProof(
  tree: Buffer[][],
  leafIndex: number,
): MerkleProofItem[] {
  const proof: MerkleProofItem[] = [];
  let idx = leafIndex;

  for (let level = 0; level < tree.length - 1; level++) {
    const levelNodes = tree[level];
    const isRightChild = idx % 2 === 1;
    const sibIdx = isRightChild ? idx - 1 : idx + 1;

    if (sibIdx < levelNodes.length) {
      proof.push({
        siblingHash: levelNodes[sibIdx],
        isLeft: isRightChild, // sibling is left when current is right
      });
    }

    idx = Math.floor(idx / 2);
  }

  return proof;
}

// ---------------------------------------------------------------------------
// Verify a Merkle proof (useful in tests and the off-chain challenge responder)
// ---------------------------------------------------------------------------
export function verifyMerkleProof(
  leafHash: Buffer,
  proof: MerkleProofItem[],
  merkleRoot: Buffer,
): boolean {
  let current = leafHash;

  for (const { siblingHash, isLeft } of proof) {
    const combined = isLeft
      ? Buffer.concat([siblingHash, current])
      : Buffer.concat([current, siblingHash]);
    current = Buffer.from(
      blake2b(32, null, null, Buffer.from("ckb-default-hash"))(combined),
    );
  }

  return current.equals(merkleRoot);
}

// ---------------------------------------------------------------------------
// MerkleTree class — full tree built from file chunks
// ---------------------------------------------------------------------------
export class MerkleTree {
  private readonly tree: Buffer[][];
  readonly leaves: Buffer[];
  readonly root: Buffer;

  constructor(chunks: Uint8Array[]) {
    this.leaves = chunks.map(hashChunk);
    this.tree = buildMerkleTree(this.leaves);
    this.root = this.tree[this.tree.length - 1][0];
  }

  getRoot(): Buffer {
    return this.root;
  }

  getRootHex(): string {
    return "0x" + this.root.toString("hex");
  }

  getProof(leafIndex: number): MerkleProofItem[] {
    return getMerkleProof(this.tree, leafIndex);
  }

  verify(leafIndex: number, leafHash: Buffer): boolean {
    return verifyMerkleProof(leafHash, this.getProof(leafIndex), this.root);
  }

  get numLeaves(): number {
    return this.leaves.length;
  }
}

// ---------------------------------------------------------------------------
// Compute challenge index from block hash and deal tx hash
// Mirrors the on-chain logic: u64_le(blockHash XOR dealTxHash) % numChunks
// ---------------------------------------------------------------------------
export function computeChallengeIndex(
  blockHash: string, // hex, 0x prefixed
  dealTxHash: string, // hex, 0x prefixed
  numChunks: number,
): number {
  const bh = Buffer.from(blockHash.replace("0x", ""), "hex");
  const dt = Buffer.from(dealTxHash.replace("0x", ""), "hex");

  const xored = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) {
    xored[i] = bh[i] ^ dt[i];
  }

  // Read first 8 bytes as u64 LE
  const lo = BigInt(xored.readUInt32LE(0));
  const hi = BigInt(xored.readUInt32LE(4));
  const raw = lo + (hi << 32n);

  return Number(raw % BigInt(numChunks));
}

// ---------------------------------------------------------------------------
// Split a file buffer into 256 KB chunks
// ---------------------------------------------------------------------------
export function splitIntoChunks(fileData: Uint8Array): Uint8Array[] {
  const chunks: Uint8Array[] = [];
  for (let offset = 0; offset < fileData.length; offset += CHUNK_SIZE_BYTES) {
    chunks.push(fileData.slice(offset, offset + CHUNK_SIZE_BYTES));
  }
  return chunks;
}

// ---------------------------------------------------------------------------
// Serialize a proof path for the CKB witness
// Layout: [path_len:u32 LE] [items: 33 bytes each (32 sibling + 1 is_left)]
// ---------------------------------------------------------------------------
export function serializeMerklePath(proof: MerkleProofItem[]): Buffer {
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(proof.length, 0);

  const items = proof.map(({ siblingHash, isLeft }) => {
    const buf = Buffer.alloc(33);
    siblingHash.copy(buf, 0);
    buf[32] = isLeft ? 1 : 0;
    return buf;
  });

  return Buffer.concat([lenBuf, ...items]);
}
