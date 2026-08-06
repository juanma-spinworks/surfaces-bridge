import assert from "node:assert/strict";
import test from "node:test";

import { resolveSurfaceOrigin } from "../origin-policy.mjs";

test("accepts only the exact production Surface origins", () => {
  assert.equal(
    resolveSurfaceOrigin("https://surfaces.spinworks.ai/"),
    "https://surfaces.spinworks.ai",
  );
  assert.equal(
    resolveSurfaceOrigin("https://surfaces.slangworks.com"),
    "https://surfaces.slangworks.com",
  );
  assert.equal(
    resolveSurfaceOrigin(
      "https://surfaces-agent-api-1091410357131.us-east1.run.app",
    ),
    "https://surfaces-agent-api-1091410357131.us-east1.run.app",
  );
  assert.throws(
    () => resolveSurfaceOrigin("https://surfaces.spinworks.ai.attacker.test"),
    /untrusted Surface origin/u,
  );
});

test("rejects plaintext, credentials, ports, paths, queries, and fragments", () => {
  for (const origin of [
    "http://surfaces.spinworks.ai",
    "https://user:pass@surfaces.spinworks.ai",
    "https://surfaces.spinworks.ai:8443",
    "https://surfaces.spinworks.ai/pair",
    "https://surfaces.spinworks.ai?redirect=attacker",
    "https://surfaces.spinworks.ai#pair",
  ]) {
    assert.throws(() => resolveSurfaceOrigin(origin));
  }
});

test("permits loopback only with the explicit local-development option", () => {
  assert.throws(
    () => resolveSurfaceOrigin("http://127.0.0.1:3000"),
    /untrusted Surface origin/u,
  );
  assert.equal(
    resolveSurfaceOrigin("http://127.0.0.1:3000", { allowLocal: true }),
    "http://127.0.0.1:3000",
  );
  assert.equal(
    resolveSurfaceOrigin("https://localhost:8788", { allowLocal: true }),
    "https://localhost:8788",
  );
  assert.throws(() =>
    resolveSurfaceOrigin("https://attacker.test", { allowLocal: true }),
  );
});
