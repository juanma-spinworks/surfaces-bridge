#!/usr/bin/env node

import {
  createHash,
  generateKeyPairSync,
  randomUUID,
  sign,
} from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { homedir, platform } from "node:os";
import { join } from "node:path";

const PROTOCOL_VERSION = "surfaces.coms.v1";
const BRIDGE_KIND = "surfaces-bridge";
const BRIDGE_VERSION = "0.1.0";
const KEYCHAIN_SERVICE = "com.slangworks.surfaces.bridge";
const METADATA_DIRECTORY = join(
  homedir(),
  ".config",
  "surfaces",
  "connections",
);

const [command, ...argumentList] = process.argv.slice(2);
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

async function connect(args) {
  const origin = required(args, "origin").replace(/\/+$/u, "");
  const code = required(args, "code");
  assertMacKeychain();

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

  const signature = sign(null, Buffer.from(challenge.message), privateKey);
  const completed = await jsonFetch(
    `${origin}/api/agent/connect/complete`,
    {
      method: "POST",
      body: JSON.stringify({
        connectionId: challenge.connectionId,
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

  const credential = {
    origin,
    connectionId: connection.connectionId,
    accessToken: connection.accessToken,
    tokenExpiresAt: connection.tokenExpiresAt,
    refreshToken: connection.refreshToken,
    refreshTokenExpiresAt: connection.refreshTokenExpiresAt,
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
  };
  saveCredential(connection.connectionId, credential);
  saveMetadata({
    connectionId: connection.connectionId,
    origin,
    clientKind: BRIDGE_KIND,
    clientVersion: BRIDGE_VERSION,
    role: connection.role,
    tokenExpiresAt: connection.tokenExpiresAt,
    refreshTokenExpiresAt: connection.refreshTokenExpiresAt,
    connectedAt: new Date().toISOString(),
  });

  writeJson({
    connected: true,
    connectionId: connection.connectionId,
    role: connection.role,
    tokenExpiresAt: connection.tokenExpiresAt,
    next: `surfaces-bridge context --connection ${connection.connectionId}`,
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

function saveCredential(connectionId, credential) {
  const encoded = Buffer.from(JSON.stringify(credential)).toString("base64");
  execFileSync("security", [
    "add-generic-password",
    "-U",
    "-a",
    connectionId,
    "-s",
    KEYCHAIN_SERVICE,
    "-w",
    encoded,
  ]);
}

function loadCredential(connectionId) {
  assertMacKeychain();
  let encoded;
  try {
    encoded = execFileSync(
      "security",
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
  return JSON.parse(Buffer.from(encoded, "base64").toString("utf8"));
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
  if (args.connection) return args.connection;
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
  return entries[0].replace(/\.json$/u, "");
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
  surfaces-bridge connect --origin <url> --code <SURF-code>
  surfaces-bridge context [--connection <id>] [--cursor <event-id>]
  surfaces-bridge event [--connection <id>] --file <event.json>
  surfaces-bridge presence [--connection <id>]
  surfaces-bridge refresh [--connection <id>]
  surfaces-bridge status [--connection <id>]

The private device key and access token are stored in macOS Keychain.
`);
}
