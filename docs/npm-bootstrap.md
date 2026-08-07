# npm publication and trusted-release ceremony

The package name is reserved by product decision but cannot be published until
SpinWorks owns the `spinworks-ai` npm organization.

## Organization setup

1. Sign in to npm with the SpinWorks maintainer account.
2. Create the `spinworks-ai` organization using the free public-packages plan.
3. Require two-factor authentication for maintainers and package changes.
4. Confirm that `@spinworks-ai/surfaces-bridge` is unclaimed.

## First publication

npm staged publishing cannot create a brand-new package. The first release must
therefore be a narrowly controlled bootstrap:

1. Create the public-repository GitHub environment `npm-production`. Restrict it
   to `main`, require a maintainer review, and disallow administrator bypass if
   the repository plan supports that rule.
2. Confirm `main` CI is green, then create and push the immutable tag `v0.1.0`
   at the exact current `main` commit.
   Before tagging, confirm `release-source-manifest.json` names the exact green
   application commit and that its two SHA-256 values match that commit's
   bridge and origin-policy sources.
3. Create a shortest-lived granular access token with:
   - **Bypass 2FA** enabled, because the first direct publication is
     noninteractive;
   - **Packages and scopes** Read and write access to the `@spinworks-ai`
     scope, not merely Organizations permission; and
   - no unrelated package, organization-management, or user-management access.
   Put it only in the `npm-production` environment secret
   `NPM_BOOTSTRAP_TOKEN`. This is a one-release bootstrap exception: npm
   requires interactive 2FA or a write token with Bypass 2FA for direct
   package creation.
4. Run **Release npm package** from `main` with:
   - version: `0.1.0`
   - mode: `bootstrap`
   - confirmation:
     `publish @spinworks-ai/surfaces-bridge@0.1.0`
5. Inspect the completed candidate job, its package fingerprint, and the exact
   source commit before approving the environment deployment.
6. The guarded job publishes with
   `npm publish --access public --provenance`, compares the live registry
   integrity with the approved candidate, and runs `npm audit signatures` from
   a clean temporary consumer.
7. Delete the GitHub environment secret and revoke the Bypass-2FA bootstrap
   token immediately after the verified release, then verify both are absent.
8. Preserve the workflow run and `verified-release-0.1.0` evidence artifact,
   then repeat clean-Mac Codex and Claude enrollment before external alpha.

The workflow pins Node.js 22.14.0, npm CLI 11.15.0, and every GitHub-owned
action to an immutable commit. It refuses a branch other than public `main`, a
source commit that differs from `origin/main`, a missing or mismatched
`vVERSION` tag, a dirty checkout, or a mistyped human confirmation.

## Subsequent publications

After the package exists:

1. Configure its npm trusted publisher with:
   - GitHub owner: `juanma-spinworks`
   - repository: `surfaces-bridge`
   - workflow filename: `release.yml`
   - environment: `npm-production`
   - allowed action: stage-only `npm stage publish`
2. In package publishing access, select
   **Require two-factor authentication and disallow tokens**.
3. Remove any remaining npm publication token.
4. For each later version, merge and test the version bump, tag the exact
   current `main`, then run the workflow in `trusted-stage` mode with the exact
   confirmation `stage @spinworks-ai/surfaces-bridge@VERSION`.
5. Inspect the staged tarball on npm, approve it with maintainer 2FA, and
   independently verify registry integrity, signatures, provenance, and
   clean-machine execution before Surfaces emits the new version.

Trusted staging uses GitHub OIDC and carries no npm token. The npm package must
already exist because staged publishing cannot create a brand-new package.
