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
const VERSION_PATTERN = /\b\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\b/u;
const OS_VERSION_PATTERN = /\b\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?\b/u;
const PROVIDERS = new Set(["codex", "claude"]);
const CONNECTION_STAGES = new Set([
  "input_validation",
  "platform_check",
  "capability_detection",
  "credential_store_preflight",
  "key_generation",
  "pairing_start",
  "proof_completion",
  "credential_store",
  "context",
  "presence",
]);
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
    } else if (command === "diagnose") {
      await diagnose(argumentsByName);
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
    const diagnostic = diagnosticFromError(error);
    if (command === "connect") {
      await reportConnectionFailure(argumentsByName, diagnostic).catch(
        () => undefined,
      );
    }
    process.stderr.write(`${JSON.stringify(diagnostic)}\n`);
    process.exitCode = 1;
  }
}

async function connect(args) {
  const input = await connectionStage(
    "input_validation",
    "connection_input_invalid",
    "Use the exact generated prompt without editing its origin, code, or provider.",
    () => {
      const allowLocalOrigin = args["allow-local-origin"] === true;
      return {
        allowLocalOrigin,
        code: required(args, "code"),
        origin: resolveSurfaceOrigin(required(args, "origin"), {
          allowLocal: allowLocalOrigin,
        }),
        provider: requiredProvider(args),
      };
    },
  );
  await connectionStage(
    "platform_check",
    "unsupported_local_platform",
    "Run this beta connection on a supported Mac with the system security and expect tools.",
    () => assertMacKeychain(),
  );
  const capability = await connectionStage(
    "capability_detection",
    "provider_capability_unavailable",
    `Install or update the ${input.provider} CLI, confirm it runs on this Mac, and retry the same unexpired prompt.`,
    () => detectProviderCapability(input.provider),
  );
  await connectionStage(
    "credential_store_preflight",
    "keychain_preflight_failed",
    "Approve macOS Keychain access for this bridge command, then retry the same unexpired prompt.",
    () => assertKeychainWritable(),
  );

  const { publicKey, privateKey } = await connectionStage(
    "key_generation",
    "device_key_generation_failed",
    "Retry on the supported Mac. If this repeats, create a fresh pairing and report the diagnostic code.",
    () => generateKeyPairSync("ed25519"),
  );
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  const publicKeyRaw = publicDer.subarray(publicDer.length - 32);
  const start = await connectionStage(
    "pairing_start",
    "pairing_start_failed",
    "Check the failure details. If the credential expired or was used, create a fresh connection prompt and retry.",
    () =>
      jsonFetch(`${input.origin}/api/agent/connect/start`, {
        method: "POST",
        body: JSON.stringify({
          protocolVersion: PROTOCOL_VERSION,
          clientKind: BRIDGE_KIND,
          clientVersion: BRIDGE_VERSION,
          capability,
          code: input.code,
          publicKey: encodeBase64Url(publicKeyRaw),
        }),
      }),
  );
  const challenge = start.challenge;
  if (!challenge?.message || !challenge.connectionId) {
    throw new BridgeDiagnosticError({
      code: "pairing_challenge_invalid",
      stage: "pairing_start",
      message: "The Surface returned an invalid connection challenge.",
      repair: "Create a fresh connection prompt and retry with the current bridge.",
    });
  }
  const challengeConnectionId = assertConnectionId(
    challenge.connectionId,
  );

  const signature = sign(null, Buffer.from(challenge.message), privateKey);
  const completed = await connectionStage(
    "proof_completion",
    "proof_completion_failed",
    "Create a fresh connection prompt and retry on the same Mac.",
    () =>
      jsonFetch(
        `${input.origin}/api/agent/connect/complete`,
        {
          method: "POST",
          body: JSON.stringify({
            connectionId: challengeConnectionId,
            challengeId: challenge.challengeId,
            nonce: challenge.nonce,
            signature: encodeBase64Url(signature),
          }),
        },
      ),
  );
  const connection = completed.connection;
  if (!connection?.accessToken) {
    throw new BridgeDiagnosticError({
      code: "bounded_session_missing",
      stage: "proof_completion",
      message: "The Surface did not issue a bounded agent session.",
      repair: "Revoke the incomplete connection, create a fresh prompt, and retry.",
    });
  }
  const connectionId = assertConnectionId(connection.connectionId);

  const credential = {
    origin: input.origin,
    connectionId,
    accessToken: connection.accessToken,
    tokenExpiresAt: connection.tokenExpiresAt,
    refreshToken: connection.refreshToken,
    refreshTokenExpiresAt: connection.refreshTokenExpiresAt,
    privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
    ...(input.allowLocalOrigin ? { allowLocalOrigin: true } : {}),
  };
  await connectionStage(
    "credential_store",
    "credential_store_failed",
    "Ask the human to revoke this incomplete connection, approve Keychain access, and create a fresh prompt.",
    () => {
      saveCredential(connectionId, credential);
      saveMetadata({
        connectionId,
        origin: input.origin,
        clientKind: BRIDGE_KIND,
        clientVersion: BRIDGE_VERSION,
        capability,
        role: connection.role,
        tokenExpiresAt: connection.tokenExpiresAt,
        refreshTokenExpiresAt: connection.refreshTokenExpiresAt,
        connectedAt: new Date().toISOString(),
      });
    },
  );

  const roleContext = await connectionStage(
    "context",
    "initial_context_failed",
    "Run the context command with this connection ID. If authorization fails, ask the human to revoke and re-pair.",
    () =>
      signedFetch(
        credential,
        "GET",
        "/api/agent/context",
      ),
  );
  const presence = await connectionStage(
    "presence",
    "initial_presence_failed",
    "Run the presence command with this connection ID. Surfaces will not show the agent active until a live lease succeeds.",
    () =>
      signedFetch(
        credential,
        "POST",
        "/api/agent/presence",
        { state: "online" },
      ),
  );

  writeJson({
    connected: true,
    connectionId,
    capability,
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

async function diagnose(args) {
  const provider = await connectionStage(
    "input_validation",
    "connection_input_invalid",
    "Run diagnose with --provider codex or --provider claude.",
    () => requiredProvider(args),
  );
  await connectionStage(
    "platform_check",
    "unsupported_local_platform",
    "Run this beta connection on a supported Mac with the system security and expect tools.",
    () => assertMacKeychain(),
  );
  const capability = await connectionStage(
    "capability_detection",
    "provider_capability_unavailable",
    `Install or update the ${provider} CLI, confirm it runs on this Mac, and retry.`,
    () => detectProviderCapability(provider),
  );
  await connectionStage(
    "credential_store_preflight",
    "keychain_preflight_failed",
    "Approve macOS Keychain access for the bridge and retry.",
    () => assertKeychainWritable(),
  );
  writeJson({
    ready: true,
    capability,
    bridge: {
      kind: BRIDGE_KIND,
      version: BRIDGE_VERSION,
    },
    checks: [
      "supported macOS runtime",
      `${provider} CLI version`,
      "Node.js version",
      "transient non-secret Keychain write and cleanup",
    ],
    networkContacted: false,
    pairingCredentialConsumed: false,
  });
}

async function reportConnectionFailure(args, diagnostic) {
  if (
    !CONNECTION_STAGES.has(diagnostic.stage) ||
    diagnostic.stage === "input_validation" ||
    typeof diagnostic.code !== "string" ||
    !/^[a-z][a-z0-9_]{2,63}$/u.test(diagnostic.code)
  ) {
    return;
  }
  const allowLocalOrigin = args["allow-local-origin"] === true;
  const origin = resolveSurfaceOrigin(required(args, "origin"), {
    allowLocal: allowLocalOrigin,
  });
  const code = required(args, "code");
  await fetch(`${origin}/api/agent/connect/attempt`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      code,
      failureStage: diagnostic.stage,
      failureCode: diagnostic.code,
    }),
    signal: AbortSignal.timeout(3_000),
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

export class BridgeDiagnosticError extends Error {
  constructor({ code, stage, message, repair, status }) {
    super(message);
    this.name = "BridgeDiagnosticError";
    this.code = code;
    this.stage = stage;
    this.repair = repair;
    this.status = status;
  }
}

async function connectionStage(stage, code, repair, action) {
  if (!CONNECTION_STAGES.has(stage)) {
    throw new Error("The bridge contains an unknown connection stage.");
  }
  try {
    return await action();
  } catch (error) {
    if (error instanceof BridgeDiagnosticError) throw error;
    throw new BridgeDiagnosticError({
      code,
      stage,
      message: error instanceof Error ? error.message : "The operation failed.",
      repair,
      status:
        error && typeof error === "object" && "status" in error
          ? error.status
          : undefined,
    });
  }
}

export function diagnosticFromError(error) {
  if (error instanceof BridgeDiagnosticError) {
    return {
      ok: false,
      code: error.code,
      stage: error.stage,
      message: error.message,
      repair: error.repair,
      ...(Number.isInteger(error.status) ? { httpStatus: error.status } : {}),
    };
  }
  return {
    ok: false,
    code: "bridge_command_failed",
    stage: "command",
    message: error instanceof Error ? error.message : String(error),
    repair: "Check the command arguments and retry.",
  };
}

export function detectProviderCapability(
  provider,
  run = execFileSync,
  environment = {},
) {
  const selectedProvider = normalizeProvider(provider);
  const currentPlatform = environment.platform ?? platform();
  if (currentPlatform !== "darwin") {
    throw new Error("The Instant connection beta currently requires macOS.");
  }
  const providerOutput = run(selectedProvider, ["--version"], {
    encoding: "utf8",
    env: {
      HOME: environment.home ?? homedir(),
      PATH:
        environment.path ??
        process.env.PATH ??
        "/usr/local/bin:/usr/bin:/bin",
      NO_COLOR: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 10_000,
  });
  const platformOutput = run(
    "/usr/bin/sw_vers",
    ["-productVersion"],
    {
      encoding: "utf8",
      env: {
        PATH: "/usr/bin:/bin",
      },
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 5_000,
    },
  );
  return {
    provider: selectedProvider,
    providerVersion: readDetectedVersion(providerOutput, selectedProvider),
    nodeVersion: readDetectedVersion(
      environment.nodeVersion ?? process.versions.node,
      "Node.js",
    ),
    platform: "macos",
    platformVersion: readDetectedVersion(
      platformOutput,
      "macOS",
      OS_VERSION_PATTERN,
    ),
  };
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
    const message =
      typeof payload.error === "string"
        ? payload.error
        : `The Surface returned HTTP ${response.status}.`;
    if (
      typeof payload.code === "string" &&
      typeof payload.stage === "string" &&
      typeof payload.repair === "string"
    ) {
      throw new BridgeDiagnosticError({
        code: payload.code,
        stage: payload.stage,
        message,
        repair: payload.repair,
        status: response.status,
      });
    }
    const responseError = new Error(message);
    responseError.status = response.status;
    throw responseError;
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

function requiredProvider(args) {
  return normalizeProvider(required(args, "provider"));
}

function normalizeProvider(value) {
  if (typeof value !== "string" || !PROVIDERS.has(value.toLowerCase())) {
    throw new Error("--provider must be codex or claude.");
  }
  return value.toLowerCase();
}

function readDetectedVersion(value, label, pattern = VERSION_PATTERN) {
  const match = String(value).match(pattern);
  if (!match) {
    throw new Error(`${label} did not report a recognizable version.`);
  }
  return match[0];
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
  surfaces-bridge diagnose --provider <codex|claude>
  surfaces-bridge connect --origin <url> --code <SURF-code> --provider <codex|claude> [--allow-local-origin]
  surfaces-bridge context [--connection <id>] [--cursor <event-id>]
  surfaces-bridge event [--connection <id>] --file <event.json>
  surfaces-bridge presence [--connection <id>]
  surfaces-bridge refresh [--connection <id>]
  surfaces-bridge status [--connection <id>]

diagnose contacts no network service and consumes no pairing credential.
The private device key and access token are stored in macOS Keychain.
`);
}
