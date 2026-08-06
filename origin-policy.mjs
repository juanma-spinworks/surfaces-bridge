const TRUSTED_SURFACE_ORIGINS = new Set([
  "https://agents.surfaces.spinworks.ai",
  "https://surfaces.spinworks.ai",
  "https://surfaces.slangworks.com",
  "https://surfaces-slangworks.chipionero.chatgpt.site",
]);

const LOOPBACK_HOSTNAMES = new Set(["127.0.0.1", "[::1]", "localhost"]);

export function resolveSurfaceOrigin(rawOrigin, options = {}) {
  let url;
  try {
    url = new URL(rawOrigin);
  } catch {
    throw new Error("The Surface origin must be a valid URL.");
  }

  if (
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  ) {
    throw new Error(
      "The Surface origin must not include credentials, a path, a query, or a fragment.",
    );
  }

  if (TRUSTED_SURFACE_ORIGINS.has(url.origin)) {
    return url.origin;
  }

  if (
    options.allowLocal === true &&
    LOOPBACK_HOSTNAMES.has(url.hostname) &&
    (url.protocol === "http:" || url.protocol === "https:")
  ) {
    return url.origin;
  }

  throw new Error(
    "Refusing an untrusted Surface origin. Use an official SpinWorks Surfaces origin, or --allow-local-origin with a loopback URL for local development.",
  );
}
