import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const PACKAGE_NAME = "@spinworks-ai/surfaces-bridge";
const REPOSITORY = "juanma-spinworks/surfaces-bridge";

function required(name) {
  const value = process.env[name]?.trim();
  assert.ok(value, `${name} is required`);
  return value;
}

const manifest = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
);
const version = required("RELEASE_VERSION");
const mode = required("RELEASE_MODE");
const confirmation = required("RELEASE_CONFIRMATION");
const githubSha = required("GITHUB_SHA");

assert.equal(process.env.GITHUB_EVENT_NAME, "workflow_dispatch");
assert.equal(process.env.GITHUB_REPOSITORY, REPOSITORY);
assert.equal(process.env.GITHUB_REF, "refs/heads/main");
assert.match(githubSha, /^[0-9a-f]{40}$/u);
assert.equal(manifest.name, PACKAGE_NAME);
assert.equal(version, manifest.version);
assert.ok(["bootstrap", "trusted-stage"].includes(mode), "invalid release mode");

const confirmationVerb = mode === "bootstrap" ? "publish" : "stage";
assert.equal(
  confirmation,
  `${confirmationVerb} ${PACKAGE_NAME}@${version}`,
  "human confirmation does not match the exact release",
);

const git = (...args) =>
  execFileSync("git", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();

assert.equal(git("rev-parse", "HEAD"), githubSha, "checkout differs from event");
assert.equal(
  git("rev-parse", "origin/main"),
  githubSha,
  "release must be the current public main commit",
);
assert.equal(
  git("rev-parse", `refs/tags/v${version}^{commit}`),
  githubSha,
  `v${version} must identify the exact main commit`,
);
assert.equal(git("status", "--porcelain"), "", "release checkout must be clean");

process.stdout.write(
  `${PACKAGE_NAME}@${version} ${mode} preflight passed at ${githubSha}\n`,
);
