# Controlled OIDC provider lab

This repository hosts a minimal static OpenID Connect discovery document and JWKS for authorized testing of the researcher-owned 1Password Credential Broker tenant.

It contains no 1Password credentials, integration keys, Environment values, or production identity material. The signing private key remains local and is ignored by Git.

Published issuer:

```text
https://pauljones0.github.io/onepassword-oidc-provider-lab
```

## Planned verifier matrix

After establishing one valid baseline token, test one variable at a time:

1. wrong and missing `aud`;
2. expired token and future `nbf`;
3. wrong `iss` with a valid signature;
4. `alg: none`;
5. HS256 using the published RSA key as the HMAC secret;
6. untrusted `jku` and `x5u` header URLs;
7. unknown and colliding `kid` values;
8. scalar versus array audiences;
9. JWKS rotation and cache invalidation;
10. token replay after workload access is revoked;
11. cross-integration and cross-tenant issuer/key confusion using only researcher-owned tenants.

Every probe must retrieve only a synthetic canary from a researcher-owned Environment and record presence plus a digest, never the raw value.

## Mint a token

```sh
node scripts/mint-token.mjs --aud onepassword-lab
```

Additional negative-test flags include `--alg none`, `--alg HS256`, `--omit-aud`, `--aud-array`, `--iss`, `--exp-offset`, `--nbf-offset`, `--kid`, `--jku`, and `--x5u`.

