import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(import.meta.dirname, "..");
const bridgeDirectory = repositoryRoot;
const consumerRoot = mkdtempSync(
  join(tmpdir(), "surfaces-bridge-clean-consumer-"),
);

function run(command, argumentsList, options = {}) {
  const result = spawnSync(command, argumentsList, {
    encoding: "utf8",
    timeout: 30_000,
    ...options,
  });
  assert.equal(
    result.error,
    undefined,
    `${command} could not start: ${result.error?.message}`,
  );
  assert.equal(
    result.signal,
    null,
    `${command} was terminated by ${result.signal}`,
  );
  assert.equal(
    result.status,
    0,
    `${command} failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  return result;
}

try {
  const packDirectory = join(consumerRoot, "pack");
  const cacheDirectory = join(consumerRoot, "cache");
  const npmUserConfig = join(consumerRoot, "npmrc");
  const npmGlobalConfig = join(consumerRoot, "global-npmrc");
  mkdirSync(packDirectory, { recursive: true });
  mkdirSync(cacheDirectory, { recursive: true });
  writeFileSync(npmUserConfig, "", { mode: 0o600 });
  writeFileSync(npmGlobalConfig, "", { mode: 0o600 });

  const packed = run("npm", [
    "pack",
    bridgeDirectory,
    "--json",
    "--ignore-scripts",
    "--pack-destination",
    packDirectory,
  ]);
  const packResult = JSON.parse(packed.stdout);
  assert.equal(packResult.length, 1);
  const candidate = packResult[0];
  assert.equal(candidate.name, "@spinworks-ai/surfaces-bridge");
  assert.equal(candidate.version, "0.1.0");
  assert.deepEqual(
    candidate.files.map(({ path }) => path).sort(),
    [
      "LICENSE",
      "README.md",
      "origin-policy.mjs",
      "package.json",
      "release-source-manifest.json",
      "surfaces-bridge.mjs",
    ],
  );

  const tarballPath = join(packDirectory, candidate.filename);
  const tarball = readFileSync(tarballPath);
  assert.equal(
    candidate.integrity,
    `sha512-${createHash("sha512").update(tarball).digest("base64")}`,
    "npm pack integrity must match the exact consumer tarball",
  );
  assert.equal(
    candidate.shasum,
    createHash("sha1").update(tarball).digest("hex"),
    "npm pack shasum must match the exact consumer tarball",
  );

  const consumer = run(
    "npm",
    [
      "exec",
      "--yes",
      "--offline",
      "--ignore-scripts",
      "--cache",
      cacheDirectory,
      "--userconfig",
      npmUserConfig,
      "--globalconfig",
      npmGlobalConfig,
      "--package",
      tarballPath,
      "--",
      "surfaces-bridge",
    ],
    {
      cwd: consumerRoot,
      env: {
        CI: "true",
        PATH: process.env.PATH,
        TMPDIR: consumerRoot,
        npm_config_audit: "false",
        npm_config_fund: "false",
        npm_config_registry: "https://registry.invalid",
        npm_config_update_notifier: "false",
      },
    },
  );
  assert.match(consumer.stdout, /^Surfaces reference bridge$/mu);
  assert.match(consumer.stdout, /^Usage:$/mu);
  assert.match(
    consumer.stdout,
    /surfaces-bridge connect --origin <url> --code <SURF-code>/u,
  );
  assert.doesNotMatch(
    `${consumer.stdout}\n${consumer.stderr}`,
    /github\.com|git@|gh[pousr]_[A-Za-z0-9_]{20,}|npm_[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]+PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/u,
    "clean artifact execution must not require or print repository credentials",
  );

  process.stdout.write(
    `${candidate.name}@${candidate.version} clean packed-artifact consumer passed: ${candidate.integrity}\n`,
  );
} finally {
  rmSync(consumerRoot, { recursive: true, force: true });
}
