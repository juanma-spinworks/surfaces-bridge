import assert from "node:assert/strict";
import test from "node:test";

import {
  KEYCHAIN_WRITE_SCRIPT,
  assertKeychainWritable,
  encodeCredentialForKeychain,
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

test("credential rotation removes the previous revision after commit", () => {
  const keychain = createKeychainHarness();
  saveCredential(credential.connectionId, credential, keychain.run);
  const previousChunks = [...keychain.entries.keys()].filter(
    (account) => account !== credential.connectionId,
  );
  const rotated = { ...credential, refreshToken: "rotated-refresh-token" };

  saveCredential(credential.connectionId, rotated, keychain.run);

  assert.deepEqual(
    loadCredential(
      credential.connectionId,
      keychain.run,
      () => undefined,
    ),
    rotated,
  );
  assert.ok(previousChunks.every((account) => !keychain.entries.has(account)));
});

test("a partial write preserves the previous readable revision", () => {
  const keychain = createKeychainHarness();
  saveCredential(credential.connectionId, credential, keychain.run);
  const previousEntries = new Map(keychain.entries);
  keychain.failNextWrite("partial");

  assert.throws(
    () =>
      saveCredential(
        credential.connectionId,
        { ...credential, refreshToken: "uncommitted-refresh-token" },
        keychain.run,
      ),
    /revoke this connection and pair again/iu,
  );
  assert.deepEqual(keychain.entries, previousEntries);
  assert.deepEqual(
    loadCredential(
      credential.connectionId,
      keychain.run,
      () => undefined,
    ),
    credential,
  );
});

test("an ambiguous helper failure accepts a complete committed revision", () => {
  const keychain = createKeychainHarness();
  saveCredential(credential.connectionId, credential, keychain.run);
  const previousChunks = [...keychain.entries.keys()].filter(
    (account) => account !== credential.connectionId,
  );
  const rotated = { ...credential, refreshToken: "committed-refresh-token" };
  keychain.failNextWrite("after_commit");

  saveCredential(credential.connectionId, rotated, keychain.run);

  assert.deepEqual(
    loadCredential(
      credential.connectionId,
      keychain.run,
      () => undefined,
    ),
    rotated,
  );
  assert.ok(previousChunks.every((account) => !keychain.entries.has(account)));
});

test("legacy single-entry credentials remain readable", () => {
  const keychain = createKeychainHarness();
  keychain.entries.set(
    credential.connectionId,
    Buffer.from(JSON.stringify(credential)).toString("base64"),
  );

  assert.deepEqual(
    loadCredential(
      credential.connectionId,
      keychain.run,
      () => undefined,
    ),
    credential,
  );
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

function createKeychainHarness() {
  const entries = new Map();
  let nextWriteFailure = null;
  return {
    entries,
    failNextWrite(mode) {
      nextWriteFailure = mode;
    },
    run(file, args, options) {
      if (file === "/usr/bin/expect") {
        const [, , countText, ...entryLines] = options.input.split("\n");
        const count = Number(countText);
        for (let index = 0; index < count; index += 1) {
          const account = entryLines[index * 2];
          const secret = entryLines[index * 2 + 1];
          entries.set(account, secret);
          if (nextWriteFailure === "partial" && index === 0) {
            nextWriteFailure = null;
            throw new Error("simulated partial write");
          }
        }
        if (nextWriteFailure === "after_commit") {
          nextWriteFailure = null;
          throw new Error("simulated ambiguous committed write");
        }
        return "";
      }
      assert.equal(file, "/usr/bin/security");
      const account = args[args.indexOf("-a") + 1];
      if (args[0] === "find-generic-password") {
        if (!entries.has(account)) throw new Error("missing item");
        return `${entries.get(account)}\n`;
      }
      assert.equal(args[0], "delete-generic-password");
      entries.delete(account);
      return "";
    },
  };
}
