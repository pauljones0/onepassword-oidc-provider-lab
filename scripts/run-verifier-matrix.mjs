#!/usr/bin/env node

import { createClient } from "@1password/sdk";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const issuer = "https://pauljones0.github.io/onepassword-oidc-provider-lab";
const untrustedJwks = `${issuer}/untrusted-jwks.json`;
const workloadUuid = process.env.OP_WORKLOAD_ID;
const environmentId = process.env.OP_ENVIRONMENT_ID;
const customerManagedSecret = process.env.OP_INTEGRATION_KEY?.replace(/=+$/, "");

if (!workloadUuid || !environmentId || !customerManagedSecret) {
  throw new Error("Set OP_WORKLOAD_ID, OP_ENVIRONMENT_ID, and OP_INTEGRATION_KEY");
}

const trustedPrivateKey = fs.readFileSync(path.join(root, ".lab-private-key.pem"));
const trustedPublicKey = fs.readFileSync(path.join(root, ".lab-public-key.pem"));
const attackerPrivateKey = fs.readFileSync(path.join(root, ".lab-attacker-private-key.pem"));

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

function tokenFor(audience, options = {}) {
  const now = Math.floor(Date.now() / 1000);
  const alg = options.alg ?? "RS256";
  const header = {
    alg,
    typ: "JWT",
    ...(options.omitKid ? {} : { kid: options.kid ?? "lab-rs256-v1" }),
    ...(options.jku ? { jku: options.jku } : {}),
    ...(options.x5u ? { x5u: options.x5u } : {}),
  };
  const payload = {
    iss: options.iss ?? issuer,
    sub: options.sub ?? "lab:workload:baseline",
    aud: options.aud ?? audience,
    iat: now,
    nbf: options.nbf ?? now - 5,
    exp: options.exp ?? now + 300,
    lab: "onepassword-authorized-research",
    role: options.role ?? "baseline",
    nonce: crypto.randomUUID(),
  };
  if (options.omitAud) delete payload.aud;
  if (options.omitExp) delete payload.exp;
  if (options.omitRole) delete payload.role;

  const encodedHeader = b64url(JSON.stringify(header));
  const encodedPayload = b64url(JSON.stringify(payload));
  const input = `${encodedHeader}.${encodedPayload}`;
  let signature = "";
  if (alg === "RS256") {
    signature = crypto
      .sign("RSA-SHA256", Buffer.from(input), options.attackerKey ? attackerPrivateKey : trustedPrivateKey)
      .toString("base64url");
  } else if (alg === "HS256") {
    signature = crypto.createHmac("sha256", trustedPublicKey).update(input).digest("base64url");
  }
  return `${input}.${signature}`;
}

const now = () => Math.floor(Date.now() / 1000);
const cases = [
  { name: "valid_baseline", expect: "allow", options: {} },
  { name: "wrong_audience", expect: "deny", options: { aud: "https://research.invalid/wrong-audience" } },
  { name: "missing_audience", expect: "deny", options: { omitAud: true } },
  { name: "audience_array_contains_expected", expect: "allow", makeOptions: (aud) => ({ aud: [aud, "secondary"] }) },
  { name: "expired", expect: "deny", makeOptions: () => ({ exp: now() - 30 }) },
  { name: "future_nbf", expect: "deny", makeOptions: () => ({ nbf: now() + 300 }) },
  { name: "missing_expiry", expect: "deny", options: { omitExp: true } },
  { name: "wrong_issuer", expect: "deny", options: { iss: "https://research.invalid/wrong-issuer" } },
  { name: "alg_none", expect: "deny", options: { alg: "none" } },
  { name: "hs256_with_rsa_public_key", expect: "deny", options: { alg: "HS256" } },
  { name: "unknown_kid_trusted_signature", expect: "deny", options: { kid: "unknown-key" } },
  { name: "missing_kid_trusted_signature", expect: "deny", options: { omitKid: true } },
  { name: "trusted_kid_wrong_signature", expect: "deny", options: { attackerKey: true } },
  {
    name: "jku_header_untrusted_key",
    expect: "deny",
    options: { attackerKey: true, kid: "untrusted-rs256-v1", jku: untrustedJwks },
  },
  {
    name: "x5u_header_untrusted_key",
    expect: "deny",
    options: { attackerKey: true, kid: "untrusted-rs256-v1", x5u: untrustedJwks },
  },
  { name: "wrong_required_claim", expect: "deny", options: { role: "untrusted" } },
  { name: "missing_required_claim", expect: "deny", options: { omitRole: true } },
  { name: "array_required_claim", expect: "deny", options: { role: ["baseline", "untrusted"] } },
];

let unexpected = 0;
for (const test of cases) {
  let actual = "allow";
  let variables = [];
  try {
    const client = await createClient({
      integrationName: "1Password custom OIDC verifier research",
      integrationVersion: "1.0.0",
      oidcFetcher: async (audience) => tokenFor(audience, test.makeOptions?.(audience) ?? test.options),
      workloadDetails: { customerManagedSecret, workloadUuid },
    });
    const response = await client.environments.getVariables(environmentId);
    variables = response.variables;
  } catch {
    actual = "deny";
  }
  const result = actual === test.expect ? "expected" : "unexpected";
  if (result === "unexpected") unexpected += 1;
  console.log(
    JSON.stringify({
      case: test.name,
      expected: test.expect,
      actual,
      result,
      variables_released: variables.length > 0 ? "yes" : "no",
    }),
  );
  await new Promise((resolve) => setTimeout(resolve, 500));
}

console.log(JSON.stringify({ summary: "custom_oidc_verifier_matrix", total: cases.length, unexpected }));
if (unexpected > 0) process.exitCode = 2;

