import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { platform, tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { KEYCHAIN_WRITE_SCRIPT } from "../surfaces-bridge.mjs";

if (platform() !== "darwin") {
  throw new Error(
    "The Keychain prompt-channel matrix must run on a macOS worker.",
  );
}

const account = "conn_test-1";
const service = "com.slangworks.surfaces.bridge";
const secret = "prompt-channel-sentinel";

function writeHelper(directory, name, body) {
  const helper = join(directory, name);
  writeFileSync(
    helper,
    [
      "#!/bin/sh",
      'printf \'%s\\n\' "$@" > "$0.argv"',
      'env > "$0.env"',
      'printf \'%s\' "$$" > "$0.pid"',
      ...body,
      "",
    ].join("\n"),
    { mode: 0o700 },
  );
  chmodSync(helper, 0o700);
  return helper;
}

function runPromptScenario({
  body,
  expectedStatus,
  name,
  assertChildStopped = false,
  timeoutSeconds = 30,
}) {
  const directory = mkdtempSync(
    join(tmpdir(), `surfaces-keychain-${name}-`),
  );
  const helper = writeHelper(directory, "fake-security", body);
  const script = KEYCHAIN_WRITE_SCRIPT.replace(
    "set timeout 30",
    `set timeout ${timeoutSeconds}`,
  );
  const result = spawnSync(
    "/usr/bin/expect",
    ["-c", script],
    {
      encoding: "utf8",
      env: {
        HOME: process.env.HOME,
        PATH: "/usr/bin:/bin",
      },
      input: `${account}\n${service}\n${helper}\n${secret}\n`,
      timeout: 10_000,
    },
  );

  try {
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.status, expectedStatus);
    assert.doesNotMatch(
      `${result.stdout}\n${result.stderr}\n${String(result.error ?? "")}`,
      new RegExp(secret, "u"),
    );

    const nestedArguments = readFileSync(`${helper}.argv`, "utf8");
    const nestedEnvironment = readFileSync(`${helper}.env`, "utf8");
    assert.equal(
      nestedArguments,
      [
        "add-generic-password",
        "-U",
        "-a",
        account,
        "-s",
        service,
        "-w",
        "",
      ].join("\n"),
    );
    assert.doesNotMatch(nestedArguments, new RegExp(secret, "u"));
    assert.doesNotMatch(nestedEnvironment, new RegExp(secret, "u"));
    if (assertChildStopped) {
      const childPid = Number(readFileSync(`${helper}.pid`, "utf8"));
      assert.throws(
        () => process.kill(childPid, 0),
        (error) => error?.code === "ESRCH",
      );
    }

    return {
      capturedSecret:
        expectedStatus === 0
          ? readFileSync(`${helper}.secret`, "utf8")
          : undefined,
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("system Expect delivers two prompts without nested argv or env exposure", () => {
  const result = runPromptScenario({
    name: "success",
    expectedStatus: 0,
    body: [
      "printf 'password data for new item: '",
      "IFS= read -r first",
      "printf '\\nretype password for new item: '",
      "IFS= read -r second",
      '[ "$first" = "$second" ] || exit 2',
      'printf \'%s\\n%s\' "$first" "$second" > "$0.secret"',
    ],
  });
  assert.equal(result.capturedSecret, `${secret}\n${secret}`);
});

test("system Expect accepts a single successful password prompt", () => {
  const result = runPromptScenario({
    name: "one-prompt-success",
    expectedStatus: 0,
    body: [
      "printf 'password data for new item: '",
      "IFS= read -r first",
      'printf \'%s\' "$first" > "$0.secret"',
    ],
  });
  assert.equal(result.capturedSecret, secret);
});

for (const scenario of [
  {
    name: "zero-prompt-eof",
    expectedStatus: 66,
    body: ["exit 0"],
  },
  {
    name: "one-prompt-nonzero",
    expectedStatus: 9,
    body: [
      "printf 'password data for new item: '",
      "IFS= read -r first",
      "exit 9",
    ],
  },
  {
    name: "two-prompt-nonzero",
    expectedStatus: 9,
    body: [
      "printf 'password data for new item: '",
      "IFS= read -r first",
      "printf '\\nretype password for new item: '",
      "IFS= read -r second",
      "exit 9",
    ],
  },
  {
    name: "third-prompt",
    expectedStatus: 65,
    assertChildStopped: true,
    body: [
      "printf 'password data for new item: '",
      "IFS= read -r first",
      "printf '\\nretype password for new item: '",
      "IFS= read -r second",
      "printf '\\npassword data for new item: '",
      "IFS= read -r third",
    ],
  },
  {
    name: "timeout",
    expectedStatus: 67,
    assertChildStopped: true,
    timeoutSeconds: 1,
    body: ["sleep 5"],
  },
]) {
  test(`system Expect rejects ${scenario.name} without leaking output`, () => {
    runPromptScenario(scenario);
  });
}
