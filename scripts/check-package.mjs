import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url)));
const source = readFileSync(
  new URL("../surfaces-bridge.mjs", import.meta.url),
  "utf8",
);

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
    test: "node --test tests/*.test.mjs && npm run check",
  },
  "npm publish lifecycle scripts must remain absent",
);
assert.deepEqual(manifest.files, [
  "README.md",
  "origin-policy.mjs",
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
  /resolveSurfaceOrigin\(required\(args, "origin"\)/u,
  "connect must validate the Surface origin before sending the pairing code",
);
assert.match(
  source,
  /credential\.origin = resolveSurfaceOrigin\(credential\.origin/u,
  "stored credentials must revalidate the Surface origin before reuse",
);

process.stdout.write(
  `${manifest.name}@${manifest.version} public package boundary passed\n`,
);
