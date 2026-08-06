import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const [manifestPath] = process.argv.slice(2);
assert.ok(manifestPath, "release manifest path is required");

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
assert.equal(
  manifest.package.integrity,
  process.env.EXPECTED_INTEGRITY,
  "approved candidate integrity changed",
);
assert.equal(
  manifest.package.shasum,
  process.env.EXPECTED_SHASUM,
  "approved candidate shasum changed",
);

process.stdout.write(
  `${manifest.package.name}@${manifest.package.version} fingerprint unchanged\n`,
);
