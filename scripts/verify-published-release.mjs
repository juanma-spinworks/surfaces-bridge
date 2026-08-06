import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const [manifestPath, receiptPath] = process.argv.slice(2);
assert.ok(manifestPath && receiptPath, "manifest and receipt paths are required");

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const packageSpec = `${manifest.package.name}@${manifest.package.version}`;
let registryDist;
let lastError;

for (let attempt = 1; attempt <= 10; attempt += 1) {
  try {
    registryDist = JSON.parse(
      execFileSync("npm", ["view", packageSpec, "dist", "--json"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }),
    );
    break;
  } catch (error) {
    lastError = error;
    await new Promise((resolve) => setTimeout(resolve, 3_000));
  }
}

if (!registryDist) {
  throw lastError ?? new Error("published package did not reach the registry");
}

assert.equal(
  registryDist.integrity,
  manifest.package.integrity,
  "registry integrity differs from the approved candidate",
);
assert.equal(
  registryDist.shasum,
  manifest.package.shasum,
  "registry shasum differs from the approved candidate",
);

const consumerDirectory = mkdtempSync(join(tmpdir(), "surfaces-bridge-audit-"));
let signatureAudit;
try {
  execFileSync("npm", ["init", "--yes"], {
    cwd: consumerDirectory,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  execFileSync(
    "npm",
    [
      "install",
      "--package-lock-only",
      "--ignore-scripts",
      "--registry=https://registry.npmjs.org",
      packageSpec,
    ],
    {
      cwd: consumerDirectory,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  signatureAudit = execFileSync("npm", ["audit", "signatures"], {
    cwd: consumerDirectory,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
} finally {
  rmSync(consumerDirectory, { recursive: true, force: true });
}

assert.match(
  signatureAudit,
  /verified registry signatures?/u,
  "npm did not report a verified registry signature",
);
assert.match(
  signatureAudit,
  /verified attestations?/u,
  "npm did not report a verified provenance attestation",
);

const receipt = {
  ...manifest,
  registry: {
    integrity: registryDist.integrity,
    shasum: registryDist.shasum,
    signaturesAndProvenanceVerified: true,
    verificationCommand: "npm audit signatures",
    verificationOutput: signatureAudit,
  },
};
writeFileSync(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
process.stdout.write(`${packageSpec} registry trust verified\n`);
