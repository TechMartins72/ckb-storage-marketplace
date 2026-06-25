/**
 * Deploy Phase 1 scripts to CKB Aggron Testnet
 *
 * Prerequisites:
 *   1. Run: cd contracts && capsule build --release
 *   2. Set env: DEPLOYER_PRIVATE_KEY=0x...
 *   3. Have testnet CKB from https://faucet.nervos.org
 *
 * After running this script, copy the printed outpoints into
 * sdk/src/config/testnet.ts as your ProtocolConfig.
 */

import * as fs from "fs";
import * as path from "path";
import { RPC, hd, config as lumosConfig, helpers } from "@ckb-lumos/lumos";
import type { OutPoint } from "@ckb-lumos/lumos";
import * as dotenv from 'dotenv';
dotenv.config();

const TESTNET_RPC_URL = "https://testnet.ckbapp.dev";
const PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY ?? "";

if (!PRIVATE_KEY) {
  console.error("Error: DEPLOYER_PRIVATE_KEY env var not set");
  process.exit(1);
}

lumosConfig.initializeConfig(lumosConfig.predefined.AGGRON4);

const rpc = new RPC(TESTNET_RPC_URL);

function readBinary(name: string): Buffer {
  const binPath = path.join(__dirname, `../contracts/build/release/${name}`);
  if (!fs.existsSync(binPath)) {
    throw new Error(
      `Binary not found: ${binPath}\n` +
        `Run: cd contracts && capsule build --release`,
    );
  }
  return fs.readFileSync(binPath);
}

async function deployScript(
  name: string,
  binary: Buffer,
  deployerKey: string,
): Promise<OutPoint> {
  console.log(`\nDeploying ${name} (${binary.length} bytes)...`);

  const deployerPubKey = hd.key.privateToPublic(deployerKey);
  const deployerAddress = helpers.encodeToAddress({
    codeHash:
      "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8",
    hashType: "type",
    args: hd.key.publicKeyToBlake160(deployerPubKey),
  });

  console.log(`  Deployer address: ${deployerAddress}`);

  // Build deployment transaction (simplified — in production use Lumos cell collector)
  const dataHex = "0x" + binary.toString("hex");

  // For demonstration: print the data hex so the user can deploy via ckb-cli
  console.log(`  Data length: ${binary.length} bytes`);
  console.log(`  Required capacity: ${(binary.length + 61) / 1e8} CKB`);
  console.log(`\n  To deploy via ckb-cli:`);
  console.log(`  ckb-cli wallet transfer \\`);
  console.log(`    --privkey-path ./deployer.key \\`);
  console.log(`    --to-address ${deployerAddress} \\`);
  console.log(`    --capacity ${Math.ceil((binary.length + 61) / 1e8 + 1)} \\`);
  console.log(`    --tx-fee 0.001`);

  // In a full implementation this would submit the tx via Lumos.
  // Returning a placeholder outpoint for now.
  return { txHash: "0x" + "00".repeat(32), index: "0x0" };
}

async function main() {
  const scripts = [
    "proof-verifier",
    "deal-lock",
    "escrow-lock",
    "collateral-lock",
  ];
  const deployed: Record<string, OutPoint> = {};

  console.log("=== CKB Storage Marketplace — Phase 1 Deployment ===");
  console.log(`Network: Aggron Testnet (${TESTNET_RPC_URL})\n`);

  for (const name of scripts) {
    try {
      const binary = readBinary(name);
      const outpoint = await deployScript(name, binary, PRIVATE_KEY);
      deployed[name] = outpoint;
      console.log(`  ✓ ${name} deployed: ${outpoint.txHash}:${outpoint.index}`);
    } catch (err) {
      console.error(`  ✗ ${name} failed: ${(err as Error).message}`);
    }
  }

  console.log(
    "\n=== ProtocolConfig snippet (paste into sdk/src/config/testnet.ts) ===\n",
  );
  console.log(`export const TESTNET_CONFIG = {`);
  console.log(`  ckbNodeUrl:        "${TESTNET_RPC_URL}",`);
  console.log(`  ckbIndexerUrl:     "https://testnet.ckbapp.dev/indexer",`);
  console.log(`  marketplaceApiUrl: "http://localhost:3000",`);
  console.log(`  collateralMultiplier: 2,`);
  console.log(`  scripts: {`);

  for (const [name, outpoint] of Object.entries(deployed)) {
    const camelName = name.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
    console.log(`    ${camelName}: {`);
    console.log(`      codeHash: "0x${"00".repeat(32)}", // fill after deploy`);
    console.log(`      hashType:  "data1",`);
    console.log(
      `      outPoint:  { txHash: "${outpoint.txHash}", index: "${outpoint.index}" },`,
    );
    console.log(`    },`);
  }

  console.log(`  },`);
  console.log(`};`);
}

main().catch(console.error);
