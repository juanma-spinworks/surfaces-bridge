import assert from "node:assert/strict";
import test from "node:test";

import {
  BridgeDiagnosticError,
  KEYCHAIN_WRITE_SCRIPT,
  assertKeychainWritable,
  detectProviderCapability,
  diagnosticFromError,
  saveCredential,
} from "../surfaces-bridge.mjs";

const credential = {
  accessToken: "access-token-sentinel",
  connectionId: "conn_test-1",
  privateKeyPem: "private-key-sentinel",
  refreshToken: "refresh-token-sentinel",
};

test("Keychain write keeps long-lived credentials out of argv and env", () => {
  let invocation;
  saveCredential(credential.connectionId, credential, (file, args, options) => {
    invocation = { args, file, options };
  });

  assert.equal(invocation.file, "/usr/bin/expect");
  assert.equal(invocation.args.length, 2);
  assert.equal(invocation.args[0], "-c");
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

  const [account, service, securityPath, encoded, trailing] =
    invocation.options.input.split("\n");
  assert.equal(account, credential.connectionId);
  assert.equal(service, "com.slangworks.surfaces.bridge");
  assert.equal(securityPath, "/usr/bin/security");
  assert.equal(trailing, "");
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

  const [account, service, securityPath, secret, trailing] =
    invocations[0].options.input.split("\n");
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
