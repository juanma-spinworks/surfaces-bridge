import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  BridgeDiagnosticError,
  KEYCHAIN_WRITE_SCRIPT,
  assertKeychainWritable,
  detectProviderCapability,
  diagnosticFromError,
  encodeCredentialForKeychain,
  isConnectionFailure,
  loadCredential,
  saveCredential,
} from "../surfaces-bridge.mjs";

const credential = {
  accessToken: "access-token-sentinel",
  connectionId: "conn_test-1",
  privateKeyPem: "private-key-sentinel",
  refreshToken: "refresh-token-sentinel",
  origin: "https://surfaces.spinworks.ai",
};

test("Keychain write keeps long-lived credentials out of argv and env", () => {
  let invocation;
  saveCredential(credential.connectionId, credential, (file, args, options) => {
    if (file === "/usr/bin/security") {
      throw new Error("No existing item.");
    }
    invocation = { args, file, options };
  });

  assert.equal(invocation.file, "/usr/bin/expect");
  assert.equal(invocation.args.length, 2);
  assert.equal(invocation.args[0], "-c");
  assert.match(invocation.args[1], /gets stdin entry_count/u);
  assert.match(invocation.args[1], /gets stdin secret/u);
  assert.match(
    invocation.args[1],
    /\$security_path add-generic-password -U/u,
  );

  const processBoundary = JSON.stringify({
    args: invocation.args,
    env: invocation.options.env,
  });
  for (const sentinel of [
    credential.accessToken,
    credential.privateKeyPem,
    credential.refreshToken,
  ]) {
    assert.doesNotMatch(processBoundary, new RegExp(sentinel, "u"));
  }
  assert.deepEqual(invocation.options.stdio, ["pipe", "ignore", "ignore"]);
  assert.deepEqual(invocation.options.env, {
    HOME: process.env.HOME,
    PATH: "/usr/bin:/bin",
  });

  const [service, securityPath, countText, ...entryLines] =
    invocation.options.input.split("\n");
  assert.equal(service, "com.slangworks.surfaces.bridge");
  assert.equal(securityPath, "/usr/bin/security");
  const count = Number(countText);
  assert.ok(count > 2);
  assert.equal(entryLines.pop(), "");
  assert.equal(entryLines.length, count * 2);
  const entries = Array.from({ length: count }, (_, index) => ({
    account: entryLines[index * 2],
    secret: entryLines[index * 2 + 1],
  }));
  assert.equal(entries.at(-1).account, credential.connectionId);
  assert.match(
    entries.at(-1).secret,
    /^surfaces-keychain-v2:[0-9a-f]{32}:\d{1,2}:[A-Za-z0-9_-]{43}$/u,
  );
  assert.ok(entries.every((entry) => Buffer.byteLength(entry.secret) < 128));
  const encoded = entries
    .slice(0, -1)
    .map((entry) => entry.secret)
    .join("");
  assert.deepEqual(
    JSON.parse(Buffer.from(encoded, "base64").toString("utf8")),
    credential,
  );
});

test("Keychain preflight uses the exact prompt-backed path before cleanup", () => {
  const invocations = [];
  assertKeychainWritable((file, args, options) => {
    invocations.push({ args, file, options });
  });

  assert.equal(invocations.length, 2);
  assert.equal(invocations[0].file, "/usr/bin/expect");
  assert.deepEqual(invocations[0].args, ["-c", KEYCHAIN_WRITE_SCRIPT]);
  assert.deepEqual(invocations[0].options.stdio, [
    "pipe",
    "ignore",
    "ignore",
  ]);

  const [service, securityPath, count, account, secret, trailing] =
    invocations[0].options.input.split("\n");
  assert.equal(count, "1");
  assert.match(account, /^probe_[0-9a-f-]{36}$/u);
  assert.equal(service, "com.slangworks.surfaces.bridge");
  assert.equal(securityPath, "/usr/bin/security");
  assert.equal(secret, "surfaces-keychain-write-probe");
  assert.equal(trailing, "");

  assert.equal(invocations[1].file, "/usr/bin/security");
  assert.deepEqual(invocations[1].args, [
    "delete-generic-password",
    "-a",
    account,
    "-s",
    "com.slangworks.surfaces.bridge",
  ]);
  assert.deepEqual(invocations[1].options, { stdio: "ignore" });
});

test("chunked Keychain credentials round-trip with digest validation", () => {
  const stored = encodeCredentialForKeychain(
    credential.connectionId,
    credential,
  );
  const entries = new Map(
    stored.entries.map((entry) => [entry.account, entry.secret]),
  );
  const read = (file, args) => {
    assert.equal(file, "/usr/bin/security");
    assert.equal(args[0], "find-generic-password");
    const account = args[args.indexOf("-a") + 1];
    if (!entries.has(account)) throw new Error("missing item");
    return `${entries.get(account)}\n`;
  };

  assert.deepEqual(
    loadCredential(credential.connectionId, read, () => undefined),
    credential,
  );

  entries.set(stored.chunkAccounts[0], "tampered");
  assert.throws(
    () => loadCredential(credential.connectionId, read, () => undefined),
    /incomplete or damaged/u,
  );
});

test("direct CLI failures initialize the diagnostic class before execution", () => {
  const result = spawnSync(
    process.execPath,
    [
      fileURLToPath(new URL("../surfaces-bridge.mjs", import.meta.url)),
      "context",
      "--connection",
      "conn_missing-for-diagnostic-test",
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 1);
  assert.doesNotMatch(result.stderr, /ReferenceError|before initialization/u);
  assert.match(result.stderr, /"ok":false/u);
});

test("invalid connection identifiers are rejected before Keychain invocation", () => {
  for (const invalid of [
    undefined,
    null,
    123,
    true,
    false,
    "",
    "../escape",
  ]) {
    let invoked = false;
    assert.throws(
      () =>
        saveCredential(invalid, credential, () => {
          invoked = true;
        }),
      /invalid connection identifier/u,
    );
    assert.equal(invoked, false);
  }
});

test("Keychain helper failures return credential-free guidance", () => {
  assert.throws(
    () =>
      saveCredential(credential.connectionId, credential, () => {
        throw new Error(
          `${credential.accessToken}:${credential.refreshToken}:` +
            credential.privateKeyPem,
        );
      }),
    (error) => {
      assert.equal(
        error.message,
        "macOS Keychain rejected credential storage. Revoke this connection and pair again outside the provider sandbox.",
      );
      for (const sentinel of [
        credential.accessToken,
        credential.privateKeyPem,
        credential.refreshToken,
      ]) {
        assert.doesNotMatch(error.message, new RegExp(sentinel, "u"));
      }
      return true;
    },
  );
});

test("provider capability detection reports only bounded runtime versions", () => {
  const invocations = [];
  const capability = detectProviderCapability(
    "codex",
    (file, args, options) => {
      invocations.push({ file, args, options });
      return file === "codex" ? "codex-cli 0.144.1\n" : "26.6\n";
    },
    {
      platform: "darwin",
      home: "/Users/example",
      path: "/opt/homebrew/bin:/usr/bin:/bin",
      nodeVersion: "22.16.0",
    },
  );

  assert.deepEqual(capability, {
    provider: "codex",
    providerVersion: "0.144.1",
    nodeVersion: "22.16.0",
    platform: "macos",
    platformVersion: "26.6",
  });
  assert.deepEqual(
    invocations.map(({ file, args }) => ({ file, args })),
    [
      { file: "codex", args: ["--version"] },
      { file: "/usr/bin/sw_vers", args: ["-productVersion"] },
    ],
  );
  assert.doesNotMatch(JSON.stringify(invocations), /credential|pairing|prompt/u);
});

test("provider capability detection refuses unsupported providers and versions", () => {
  assert.throws(
    () =>
      detectProviderCapability("other", () => "", {
        platform: "darwin",
      }),
    /codex or claude/u,
  );
  assert.throws(
    () =>
      detectProviderCapability(
        "claude",
        (file) => (file === "claude" ? "unknown" : "26.6"),
        { platform: "darwin", nodeVersion: "22.16.0" },
      ),
    /recognizable version/u,
  );
});

test("connection failures expose a stable repairable stage", () => {
  assert.deepEqual(
    diagnosticFromError(
      new BridgeDiagnosticError({
        code: "provider_capability_unavailable",
        stage: "capability_detection",
        message: "The CLI was not found.",
        repair: "Install the selected provider CLI and retry.",
      }),
    ),
    {
      ok: false,
      code: "provider_capability_unavailable",
      stage: "capability_detection",
      message: "The CLI was not found.",
      repair: "Install the selected provider CLI and retry.",
    },
  );
});

test("connection analytics allows only fixed stage and code pairs", () => {
  assert.equal(
    isConnectionFailure(
      "capability_detection",
      "provider_capability_unavailable",
    ),
    true,
  );
  assert.equal(
    isConnectionFailure("pairing_start", "provider_capability_unavailable"),
    false,
  );
  assert.equal(
    isConnectionFailure("presence", "secret_token_abcdef"),
    false,
  );
});
