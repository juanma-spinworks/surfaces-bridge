import assert from "node:assert/strict";
import { appendFileSync, readFileSync, writeFileSync } from "node:fs";

const [packPath, outputPath] = process.argv.slice(2);
assert.ok(packPath && outputPath, "pack and output paths are required");

const packageManifest = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);
const releaseSource = JSON.parse(
  readFileSync(
    new URL("../release-source-manifest.json", import.meta.url),
    "utf8",
  ),
);
const source = readFileSync(
  new URL("../surfaces-bridge.mjs", import.meta.url),
  "utf8",
);
const packEntries = JSON.parse(readFileSync(packPath, "utf8"));
assert.equal(packEntries.length, 1, "exactly one package must be packed");

const pack = packEntries[0];
assert.equal(pack.name, packageManifest.name);
assert.equal(pack.version, packageManifest.version);
assert.match(pack.integrity, /^sha512-[A-Za-z0-9+/]+={0,2}$/u);
assert.match(pack.shasum, /^[0-9a-f]{40}$/u);

const protocolMatch = source.match(
  /const PROTOCOL_VERSION = "(?<version>[^"]+)";/u,
);
assert.ok(protocolMatch?.groups?.version, "protocol version is missing");

const githubServerUrl = process.env.GITHUB_SERVER_URL ?? "https://github.com";
const githubRepository = process.env.GITHUB_REPOSITORY;
const githubRunId = process.env.GITHUB_RUN_ID;
const githubRunAttempt = process.env.GITHUB_RUN_ATTEMPT;
const githubSha = process.env.GITHUB_SHA;
const releaseMode = process.env.RELEASE_MODE;
for (const [name, value] of Object.entries({
  GITHUB_REPOSITORY: githubRepository,
  GITHUB_RUN_ATTEMPT: githubRunAttempt,
  GITHUB_RUN_ID: githubRunId,
  GITHUB_SHA: githubSha,
  RELEASE_MODE: releaseMode,
})) {
  assert.ok(value, `${name} is required`);
}

const releaseManifest = {
  schemaVersion: 1,
  package: {
    name: pack.name,
    version: pack.version,
    filename: pack.filename,
    integrity: pack.integrity,
    shasum: pack.shasum,
    size: pack.size,
    unpackedSize: pack.unpackedSize,
  },
  protocolVersion: protocolMatch.groups.version,
  applicationSource: releaseSource.applicationSource,
  sourceFiles: releaseSource.files,
  source: {
    repository: `${githubServerUrl}/${githubRepository}`,
    commit: githubSha,
    ref: process.env.GITHUB_REF,
  },
  workflow: {
    filename: "release.yml",
    mode: releaseMode,
    runId: githubRunId,
    runAttempt: githubRunAttempt,
    url: `${githubServerUrl}/${githubRepository}/actions/runs/${githubRunId}`,
  },
};

writeFileSync(outputPath, `${JSON.stringify(releaseManifest, null, 2)}\n`);

if (process.env.GITHUB_OUTPUT) {
  appendFileSync(
    process.env.GITHUB_OUTPUT,
    [
      `integrity=${pack.integrity}`,
      `shasum=${pack.shasum}`,
      `version=${pack.version}`,
      "",
    ].join("\n"),
  );
}
