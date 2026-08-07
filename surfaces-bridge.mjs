#!/usr/bin/env node

import {
  createHash,
  generateKeyPairSync,
  randomUUID,
  sign,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

import { resolveSurfaceOrigin } from "./origin-policy.mjs";

const PROTOCOL_VERSION = "surfaces.coms.v1";
const BRIDGE_KIND = "surfaces-bridge";
const BRIDGE_VERSION = "0.1.0";
const KEYCHAIN_SERVICE = "com.slangworks.surfaces.bridge";
const CONNECTION_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/u;
export const KEYCHAIN_WRITE_SCRIPT = String.raw`
set timeout 30
log_user 0

if {[gets stdin account] < 0} { exit 64 }
if {[gets stdin service] < 0} { exit 64 }
if {[gets stdin security_path] < 0} { exit 64 }
if {[gets stdin secret] < 0} { exit 64 }

spawn -noecho $security_path add-generic-password -U -a $account -s $service -w
set prompt_count 0
expect {
  -re {(?i)password[^:]*:[[:space:]]*$} {
    incr prompt_count
    if {$prompt_count > 2} {
      catch {exec /bin/kill -TERM [exp_pid]}
      catch {close}
      catch {wait}
      exit 65
    }
    send -- "$secret\r"
    exp_continue
  }
  eof {
    set result [wait]
    if {$prompt_count < 1 || $prompt_count > 2} { exit 66 }
    exit [lindex $result 3]
  }
  timeout {
    catch {exec /bin/kill -TERM [exp_pid]}
    catch {close}
    catch {wait}
    exit 67
  }
}
`;
const METADATA_DIRECTORY = join(
  homedir(),
  ".config",
  "surfaces",
  "connections",
);

if (isDirectExecution()) {
  await runCli(process.argv.slice(2));
}

async function runCli(values) {
  const [command, ...argumentList] = values;
  const argumentsByName = parseArguments(argumentList);
  try {
    if (command === "connect") {
      await connect(argumentsByName);
    } else if (command === "context") {
      await context(argumentsByName);
    } else if (command === "event") {
      await event(argumentsByName);
    } else if (command === "presence") {
      await presence(argumentsByName);
    } else if (command === "refresh") {
      await refresh(argumentsByName);
    } else if (command === "status") {
      status(argumentsByName);
    } else {
      printUsage();
      process.exitCode = command ? 1 : 0;
    }
  } catch (error) {
    process.stderr.write(
      `Surfaces bridge: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}

async function connect(args) {
  const allowLocalOrigin = args["allow-local-origin"] === true;
  const origin = resolveSurfaceOrigin(required(args, "origin"), {
    allowLocal: allowLocalOrigin,
  });
  const code = required(args, "code");
  assertMacKeychain();
  assertKeychainWritable();

  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const publicKeyRaw = publicDer.subarray(publicDer.length - 32);
  const start = await jsonFetch(`${origin}/api/agent/connect/start`, {
    method: "POST",
    body: JSON.stringify({
      protocolVersion: PROTOCOL_VERSION,
      clientKind: BRIDGE_KIND,
      clientVersion: BRIDGE_VERSION,
      code,
      publicKey: encodeBase64Url(publicKeyRaw),
    }),
  });
  const challenge = start.challenge;
  if (!challenge?.message || !challenge.connectionId) {
    throw new Error("The Surface returned an invalid connection challenge.");
  }
  const challengeConnectionId = assertConnectionId(
    challenge.connectionId,
  );

  const signature = sign(null, Buffer.from(challenge.message), privateKey);
  const completed = await jsonFetch(
    `${origin}/api/agent/connect/complete`,
    {
      method: "POST",
      body: JSON.stringify({
        connectionId: challengeConnectionId,
        challengeId: challenge.challengeId,
        nonce: challenge.nonce,
        signature: encodeBase64Url(signature),
      }),
    },
  );
  const connection = completed.connection;
  if (!connection?.accessToken) {
    throw new Error("The Surface did not issue a bounded agent session.");
  }
  const connectionId = assertConnectionId(connection.connectionId);

  const credential = {
    origin,
    connectionId,
    accessToken: connection.accessToken,
    tokenExpiresAt: connection.tokenExpiresAt,
    refreshToken: connection.refreshToken,
    refreshTokenExpiresAt: connection.refreshTokenExpiresAt,
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    ...(allowLocalOrigin ? { allowLocalOrigin: true } : {}),
  };
  saveCredential(connectionId, credential);
  saveMetadata({
    connectionId,
    origin,
    clientKind: BRIDGE_KIND,
    clientVersion: BRIDGE_VERSION,
    role: connection.role,
    tokenExpiresAt: connection.tokenExpiresAt,
    refreshTokenExpiresAt: connection.refreshTokenExpiresAt,
    connectedAt: new Date().toISOString(),
  });

  const roleContext = await signedFetch(
    credential,
    "GET",
    "/api/agent/context",
  );
  const presence = await signedFetch(
    credential,
    "POST",
    "/api/agent/presence",
    { state: "online" },
  );

  writeJson({
    connected: true,
    connectionId,
    role: connection.role,
    tokenExpiresAt: connection.tokenExpiresAt,
    context: roleContext,
    presence,
    followUp: {
      instruction:
        "Reuse the same pinned npm exec package prefix for every follow-up bridge command.",
      connectionArgument: `--connection ${connectionId}`,
    },
  });
}

async function context(args) {
  const credential = loadCredential(resolveConnectionId(args));
  const cursor = args.cursor ? `?cursor=${encodeURIComponent(args.cursor)}` : "";
  const result = await signedFetch(
    credential,
    "GET",
    `/api/agent/context${cursor}`,
  );
  writeJson(result);
}

async function event(args) {
  const credential = loadCredential(resolveConnectionId(args));
  const payload = readEventPayload(args);
  const result = await signedFetch(
    credential,
    "POST",
    "/api/agent/events",
    payload,
  );
  writeJson(result);
}

async function presence(args) {
  const credential = loadCredential(resolveConnectionId(args));
  const result = await signedFetch(
    credential,
    "POST",
    "/api/agent/presence",
    { state: "online" },
  );
  writeJson(result);
}

async function refresh(args) {
  const credential = loadCredential(resolveConnectionId(args));
  const session = await refreshCredential(credential);
  writeJson({
    refreshed: true,
    connectionId: credential.connectionId,
    tokenExpiresAt: session.tokenExpiresAt,
    refreshTokenExpiresAt: session.refreshTokenExpiresAt,
    recovered: session.recovered,
  });
}

function status(args) {
  const connectionId = resolveConnectionId(args);
  const metadata = readMetadata(connectionId);
  writeJson({
    ...metadata,
    credentialStore: "macOS Keychain",
    tokenExpired: metadata.tokenExpiresAt <= Date.now(),
    refreshTokenExpired:
      !metadata.refreshTokenExpiresAt ||
      metadata.refreshTokenExpiresAt <= Date.now(),
  });
}

async function signedFetch(credential, method, path, payload) {
  if (
    credential.refreshToken &&
    credential.tokenExpiresAt <= Date.now() + 30_000
  ) {
    await refreshCredential(credential);
  }
  try {
    return await performSignedFetch(
      credential,
      method,
      path,
      payload,
      credential.accessToken,
    );
  } catch (error) {
    if (error?.status !== 401 || !credential.refreshToken) throw error;
    await refreshCredential(credential);
    return performSignedFetch(
      credential,
      method,
      path,
      payload,
      credential.accessToken,
    );
  }
}

async function refreshCredential(credential) {
  if (!credential.refreshToken) {
    throw new Error("This connection has no renewable session. Pair again.");
  }
  if (credential.refreshTokenExpiresAt <= Date.now()) {
    throw new Error("The refresh family expired. Pair again.");
  }
  const refreshRequestId =
    credential.pendingRefreshRequestId ?? `refresh:${randomUUID()}`;
  if (!credential.pendingRefreshRequestId) {
    credential.pendingRefreshRequestId = refreshRequestId;
    saveCredential(credential.connectionId, credential);
  }
  const payload = { refreshRequestId };
  const response = await performSignedFetch(
    credential,
    "POST",
    "/api/agent/refresh",
    payload,
    credential.refreshToken,
    refreshRequestId,
  );
  const session = response.session;
  if (!session?.accessToken || !session?.refreshToken) {
    throw new Error("The Surface returned an invalid refreshed session.");
  }
  credential.accessToken = session.accessToken;
  credential.tokenExpiresAt = session.tokenExpiresAt;
  credential.refreshToken = session.refreshToken;
  credential.refreshTokenExpiresAt = session.refreshTokenExpiresAt;
  delete credential.pendingRefreshRequestId;
  saveCredential(credential.connectionId, credential);
  saveMetadata({
    ...readMetadata(credential.connectionId),
    tokenExpiresAt: session.tokenExpiresAt,
    refreshTokenExpiresAt: session.refreshTokenExpiresAt,
    refreshedAt: new Date().toISOString(),
  });
  return session;
}

async function performSignedFetch(
  credential,
  method,
  path,
  payload,
  authorizationToken,
  requestId = `req:${randomUUID()}`,
) {
  const body = payload === undefined ? "" : JSON.stringify(payload);
  const timestamp = Date.now();
  const bodySha256 = createHash("sha256")
    .update(body)
    .digest("base64url");
  const message = [
    "surfaces.request.v1",
    method,
    credential.origin,
    path,
    String(timestamp),
    requestId,
    bodySha256,
  ].join("\n");
  const signature = sign(
    null,
    Buffer.from(message),
    credential.privateKeyPem,
  );

  return jsonFetch(`${credential.origin}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${authorizationToken}`,
      "content-type": "application/json",
      "surfaces-timestamp": String(timestamp),
      "surfaces-request-id": requestId,
      "surfaces-signature": encodeBase64Url(signature),
    },
    body: body || undefined,
  });
}

async function jsonFetch(url, init) {
  const response = await fetch(url, {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init.headers ?? {}),
    },
  });
  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new Error(`The Surface returned HTTP ${response.status}.`);
  }
  if (!response.ok) {
    const error = new Error(
      payload.error ?? `The Surface returned HTTP ${response.status}.`,
    );
    error.status = response.status;
    throw error;
  }
  return payload;
}

export function saveCredential(
  connectionId,
  credential,
  run = execFileSync,
) {
  assertConnectionId(connectionId);
  const encoded = Buffer.from(JSON.stringify(credential)).toString("base64");
  try {
    writeKeychainSecret(connectionId, encoded, run);
  } catch {
    throw new Error(
      "macOS Keychain rejected credential storage. Revoke this connection and pair again outside the provider sandbox.",
    );
  }
}

function writeKeychainSecret(
  connectionId,
  encoded,
  run = execFileSync,
  securityPath = "/usr/bin/security",
) {
  assertConnectionId(connectionId);
  run(
    "/usr/bin/expect",
    ["-c", KEYCHAIN_WRITE_SCRIPT],
    {
      encoding: "utf8",
      env: {
        HOME: homedir(),
        PATH: "/usr/bin:/bin",
      },
      input:
        `${connectionId}\n${KEYCHAIN_SERVICE}\n${securityPath}\n${encoded}\n`,
      stdio: ["pipe", "ignore", "ignore"],
      timeout: 35_000,
    },
  );
}

function loadCredential(connectionId) {
  assertMacKeychain();
  let encoded;
  try {
    encoded = execFileSync(
      "/usr/bin/security",
      [
        "find-generic-password",
        "-a",
        connectionId,
        "-s",
        KEYCHAIN_SERVICE,
        "-w",
      ],
      { encoding: "utf8" },
    ).trim();
  } catch {
    throw new Error(
      `No Keychain credential was found for ${connectionId}. Pair again.`,
    );
  }
  const credential = JSON.parse(
    Buffer.from(encoded, "base64").toString("utf8"),
  );
  credential.origin = resolveSurfaceOrigin(credential.origin, {
    allowLocal: credential.allowLocalOrigin === true,
  });
  return credential;
}

function saveMetadata(metadata) {
  mkdirSync(METADATA_DIRECTORY, { recursive: true, mode: 0o700 });
  writeFileSync(
    join(METADATA_DIRECTORY, `${metadata.connectionId}.json`),
    `${JSON.stringify(metadata, null, 2)}\n`,
    { mode: 0o600 },
  );
}

function readMetadata(connectionId) {
  try {
    return JSON.parse(
      readFileSync(
        join(METADATA_DIRECTORY, `${connectionId}.json`),
        "utf8",
      ),
    );
  } catch {
    throw new Error(`No connection metadata was found for ${connectionId}.`);
  }
}

function resolveConnectionId(args) {
  if (args.connection) return assertConnectionId(args.connection);
  let entries;
  try {
    entries = readdirSync(METADATA_DIRECTORY)
      .filter((entry) => entry.endsWith(".json"))
      .sort();
  } catch {
    entries = [];
  }
  if (entries.length !== 1) {
    throw new Error(
      "Specify --connection when zero or multiple connections exist.",
    );
  }
  return assertConnectionId(entries[0].replace(/\.json$/u, ""));
}

function readEventPayload(args) {
  if (args.file) {
    return JSON.parse(readFileSync(args.file, "utf8"));
  }
  if (args.json) return JSON.parse(args.json);
  throw new Error("event requires --file <path> or --json '<object>'.");
}

function parseArguments(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (!value.startsWith("--")) {
      throw new Error(`Unexpected argument: ${value}`);
    }
    const key = value.slice(2);
    const next = values[index + 1];
    if (!next || next.startsWith("--")) {
      parsed[key] = true;
    } else {
      parsed[key] = next;
      index += 1;
    }
  }
  return parsed;
}

function required(args, key) {
  const value = args[key];
  if (typeof value !== "string" || !value) {
    throw new Error(`--${key} is required.`);
  }
  return value;
}

function assertMacKeychain() {
  if (platform() !== "darwin") {
    throw new Error(
      "The MVP reference bridge currently requires macOS Keychain.",
    );
  }
  if (
    !existsSync("/usr/bin/security") ||
    !existsSync("/usr/bin/expect")
  ) {
    throw new Error(
      "The MVP reference bridge requires the macOS security and expect tools.",
    );
  }
}

export function assertKeychainWritable(
  run = execFileSync,
  securityPath = "/usr/bin/security",
) {
  const probeAccount = `probe_${randomUUID()}`;
  try {
    writeKeychainSecret(
      probeAccount,
      "surfaces-keychain-write-probe",
      run,
      securityPath,
    );
    run(
      securityPath,
      [
        "delete-generic-password",
        "-a",
        probeAccount,
        "-s",
        KEYCHAIN_SERVICE,
      ],
      { stdio: "ignore" },
    );
  } catch {
    try {
      run(
        securityPath,
        [
          "delete-generic-password",
          "-a",
          probeAccount,
          "-s",
          KEYCHAIN_SERVICE,
        ],
        { stdio: "ignore" },
      );
    } catch {
      // The probe was never stored or could not be removed in this sandbox.
    }
    throw new Error(
      "macOS Keychain access is unavailable. Run the bridge outside the provider sandbox or approve Keychain access before pairing.",
    );
  }
}

function assertConnectionId(connectionId) {
  if (
    typeof connectionId !== "string" ||
    !CONNECTION_ID_PATTERN.test(connectionId)
  ) {
    throw new Error("The Surface returned an invalid connection identifier.");
  }
  return connectionId;
}

function isDirectExecution() {
  if (!process.argv[1]) return false;
  try {
    return import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

function encodeBase64Url(value) {
  return Buffer.from(value).toString("base64url");
}

function writeJson(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function printUsage() {
  process.stdout.write(`Surfaces reference bridge

Usage:
  surfaces-bridge connect --origin <url> --code <SURF-code> [--allow-local-origin]
  surfaces-bridge context [--connection <id>] [--cursor <event-id>]
  surfaces-bridge event [--connection <id>] --file <event.json>
  surfaces-bridge presence [--connection <id>]
  surfaces-bridge refresh [--connection <id>]
  surfaces-bridge status [--connection <id>]

The private device key and access token are stored in macOS Keychain.
`);
}
