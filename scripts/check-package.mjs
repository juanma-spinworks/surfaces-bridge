import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));
const source = readFileSync(
  new URL("../surfaces-bridge.mjs", import.meta.url),
  "utf8",
);
const originPolicy = readFileSync(
  new URL("../origin-policy.mjs", import.meta.url),
  "utf8",
);
const readme = readFileSync(
  new URL("../README.md", import.meta.url),
  "utf8",
);
const releaseSource = JSON.parse(
  readFileSync(
    new URL("../release-source-manifest.json", import.meta.url),
    "utf8",
  ),
);

const sha256 = (value) => createHash("sha256").update(value).digest("hex");

assert.equal(manifest.name, "@spinworks-ai/surfaces-bridge");
assert.match(manifest.version, /^\d+\.\d+\.\d+$/u);
assert.equal(manifest.license, "Apache-2.0");
assert.equal(manifest.private, undefined);
assert.deepEqual(manifest.bin, {
  "surfaces-bridge": "./surfaces-bridge.mjs",
});
assert.deepEqual(
  manifest.scripts,
  {
    check:
      "node scripts/check-package.mjs && node scripts/check-release-workflow.mjs && npm pack --dry-run --json",
    test:
      "node --test tests/keychain.test.mjs tests/origin-policy.test.mjs && npm run check && npm run test:clean-consumer",
    "test:clean-consumer":
      "node scripts/check-clean-consumer.mjs",
    "test:keychain-macos":
      "node --test tests/keychain-macos.test.mjs",
  },
  "npm publish lifecycle scripts must remain absent",
);
assert.deepEqual(manifest.files, [
  "README.md",
  "origin-policy.mjs",
  "release-source-manifest.json",
  "surfaces-bridge.mjs",
]);
assert.equal(manifest.engines?.node, ">=22.14.0");
assert.equal(manifest.publishConfig?.access, "public");
assert.equal(manifest.publishConfig?.provenance, true);

for (const field of [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
  "bundledDependencies",
]) {
  assert.equal(manifest[field], undefined, `${field} must remain absent`);
}

const escapedVersion = manifest.version.replaceAll(".", "\\.");
assert.match(
  source,
  new RegExp(`const BRIDGE_VERSION = "${escapedVersion}";`, "u"),
  "executable and manifest versions must match",
);
assert.ok(source.startsWith("#!/usr/bin/env node\n"));
assert.match(
  source,
  /const roleContext = await signedFetch\(\s*credential,\s*"GET",\s*"\/api\/agent\/context"/u,
  "connect must fetch signed role context in the same ephemeral invocation",
);
assert.match(
  source,
  /const presence = await signedFetch\(\s*credential,\s*"POST",\s*"\/api\/agent\/presence"/u,
  "connect must create an explicit presence lease in the same invocation",
);
assert.doesNotMatch(
  source,
  /next: `surfaces-bridge/u,
  "connect must not return a bare command unavailable after npm exec exits",
);
assert.match(
  source,
  /assertMacKeychain\(\);\s*assertKeychainWritable\(\);\s*const \{ publicKey, privateKey \}/u,
  "Keychain writes must be proven before the pairing is consumed",
);
assert.match(
  source,
  /macOS Keychain rejected credential storage\. Revoke this connection and pair again outside the provider sandbox\./u,
  "credential-storage failures must be sanitized",
);
assert.match(
  source,
  /securityPath = "\/usr\/bin\/security"[\s\S]*run\(\s*"\/usr\/bin\/expect",\s*\["-c", KEYCHAIN_WRITE_SCRIPT\]/u,
  "Keychain writes must use the prompt-backed input channel",
);
assert.match(
  source,
  /\$\{KEYCHAIN_SERVICE\}\\n\$\{securityPath\}\\n\$\{entries\.length\}\\n/u,
  "the fixed security binary and entry count must be supplied through stdin",
);
assert.match(
  source,
  /KEYCHAIN_CHUNK_LENGTH = 96[\s\S]*surfaces-keychain-v2/u,
  "bounded credentials must use versioned sub-128-byte Keychain chunks",
);
assert.match(
  source,
  /createHash\("sha256"\)\.update\(encoded\)\.digest\("base64url"\)/u,
  "chunked Keychain credentials must carry an integrity digest",
);
assert.match(
  source,
  /Buffer\.byteLength\(entry\.secret, "utf8"\) >= 128/u,
  "the bridge must refuse secrets at the interactive Keychain limit",
);
assert.match(
  source,
  /writeKeychainSecret\(\s*probeAccount,\s*"surfaces-keychain-write-probe",\s*run,\s*securityPath/u,
  "preflight must exercise the exact prompt-backed Keychain write",
);
assert.doesNotMatch(
  source,
  /"-w",\s*encoded/u,
  "long-lived credentials must never be passed in process argv",
);
assert.match(
  source,
  /typeof connectionId !== "string" \|\|\s*!CONNECTION_ID_PATTERN\.test\(connectionId\)/u,
  "connection identifiers must reject non-string server values",
);
assert.match(
  source,
  /resolveSurfaceOrigin\(required\(args, "origin"\)/u,
  "connect must validate the Surface origin before sending the pairing code",
);
assert.match(
  source,
  /credential\.origin = resolveSurfaceOrigin\(credential\.origin/u,
  "stored credentials must revalidate the Surface origin before reuse",
);

assert.equal(releaseSource.schemaVersion, "surfaces.bridge.source.v1");
assert.deepEqual(releaseSource.package, {
  name: manifest.name,
  version: manifest.version,
});
assert.equal(
  releaseSource.applicationSource?.repository,
  "juanma-spinworks/surfaces",
);
assert.match(
  releaseSource.applicationSource?.commit ?? "",
  /^[0-9a-f]{40}$/u,
  "application source must be an exact Git commit",
);
assert.deepEqual(
  Object.keys(releaseSource.files ?? {}).sort(),
  ["origin-policy.mjs", "surfaces-bridge.mjs"],
);
assert.equal(
  releaseSource.files["surfaces-bridge.mjs"].sha256,
  sha256(source),
  "bridge source differs from the application-tested hash",
);
assert.equal(
  releaseSource.files["origin-policy.mjs"].sha256,
  sha256(originPolicy),
  "origin policy differs from the application-tested hash",
);
assert.match(
  readme,
  /https:\/\/github\.com\/juanma-spinworks\/surfaces-bridge\/security\/policy/u,
  "the packaged security-reporting link must resolve outside the tarball",
);
assert.doesNotMatch(
  readme,
  /\[SECURITY\.md\]\(SECURITY\.md\)/u,
  "the packaged README must not link to an excluded relative file",
);

process.stdout.write(
  `${manifest.name}@${manifest.version} public package boundary passed\n`,
);
