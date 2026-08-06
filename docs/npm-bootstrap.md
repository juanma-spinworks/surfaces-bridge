# npm publication bootstrap

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

1. Confirm `main` CI is green and the release commit is tagged `v0.1.0`.
2. Run `npm test` and inspect `npm pack --dry-run --json`.
3. Use a short-lived, granular npm token limited to this organization.
4. Publish the exact tagged commit from GitHub Actions with provenance:
   `npm publish --access public --provenance`.
5. Delete the bootstrap token immediately after the release.
6. Verify package contents, registry signature, provenance, and clean-machine
   execution before allowlisting `0.1.0` in Surfaces.

## Subsequent publications

After the package exists, configure this GitHub repository and its release
workflow as the npm trusted publisher. Use a protected GitHub environment,
OIDC, staged publishing, maintainer inspection, and 2FA approval. Do not retain
an npm publication token.
