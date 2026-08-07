import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const workflow = readFileSync(
  new URL("../.github/workflows/release.yml", import.meta.url),
  "utf8",
);
const preflight = readFileSync(
  new URL("./release-preflight.mjs", import.meta.url),
  "utf8",
);
const documentation = readFileSync(
  new URL("../docs/npm-bootstrap.md", import.meta.url),
  "utf8",
);

for (const expected of [
  "workflow_dispatch:",
  "group: surfaces-bridge-npm-release",
  "environment:",
  "name: npm-production",
  "id-token: write",
  "node-version: 22.14.0",
  "npm install --global npm@11.15.0",
  "npm pack --dry-run --json",
  "npm publish --access public --provenance",
  "npm stage publish --access public",
  "NODE_AUTH_TOKEN: ${{ secrets.NPM_BOOTSTRAP_TOKEN }}",
  "verify-published-release.mjs",
  "release-source-manifest.json",
]) {
  assert.match(workflow, new RegExp(expected.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "u"));
}

assert.doesNotMatch(workflow, /^\s+push:/mu, "release must not run on push");
assert.doesNotMatch(
  workflow,
  /^\s+pull_request:/mu,
  "release must not run on pull requests",
);
assert.doesNotMatch(
  workflow,
  /uses:\s+actions\/[^@\s]+@v\d+/u,
  "release actions must be pinned to immutable commits",
);
assert.equal(
  workflow.match(/NPM_BOOTSTRAP_TOKEN/gu)?.length,
  1,
  "the bootstrap token may be referenced only by the first-publish step",
);
assert.match(preflight, /refs\/heads\/main/u);
assert.match(preflight, /refs\/tags\/v\$\{version\}\^\{commit\}/u);
assert.match(preflight, /origin\/main/u);

for (const phrase of [
  "npm-production",
  "NPM_BOOTSTRAP_TOKEN",
  "npm CLI 11.15.0",
  "trusted-stage",
  "stage-only",
  "Require two-factor authentication and disallow tokens",
]) {
  assert.ok(
    documentation.includes(phrase),
    `npm bootstrap documentation must include ${phrase}`,
  );
}

process.stdout.write("npm release workflow boundary passed\n");
