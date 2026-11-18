#!/usr/bin/env node

import { createClient } from "@1password/sdk";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const issuer = "https://onepassword-oidc-provider-lab.vercel.app";
const integrationKey = process.env.OP_INTEGRATION_KEY?.replace(/=+$/, "");
const workload = process.env.OP_WORKLOAD_ID;
const environment = process.env.OP_ENVIRONMENT_ID;
const delayMs = Number(process.env.OP_SESSION_REVOCATION_DELAY_MS ?? 180_000);
const privateKey = fs.readFileSync(path.join(root, ".lab-private-key.pem"));

if (!integrationKey || !workload || !environment) {
  throw new Error("Set OP_INTEGRATION_KEY, OP_WORKLOAD_ID, and OP_ENVIRONMENT_ID");
}

const b64url = (value) => Buffer.from(value).toString("base64url");

function mintToken(audience) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: "lab-rs256-v1" };
  const payload = {
    iss: issuer,
    sub: "lab:workload:baseline",
    aud: audience,
    iat: now,
    nbf: now - 5,
    exp: now + 300,
    jti: crypto.randomUUID(),
    nonce: crypto.randomUUID(),
    lab: "onepassword-authorized-research",
    role: "baseline",
  };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(input), privateKey).toString("base64url");
  return `${input}.${signature}`;
}

let tokenRequests = 0;
const client = await createClient({
  integrationName: "Custom OIDC session revocation research",
  integrationVersion: "1.0.0",
  oidcFetcher: async (audience) => {
    tokenRequests += 1;
    return mintToken(audience);
  },
  workloadDetails: { customerManagedSecret: integrationKey, workloadUuid: workload },
});

console.log(
  JSON.stringify({
    event: "authenticated_client_ready",
    instruction: "delete_the_researcher_owned_integration_now",
    token_requests_before_deletion: tokenRequests,
    delay_ms: delayMs,
  }),
);
await new Promise((resolve) => setTimeout(resolve, delayMs));

try {
  const { variables } = await client.environments.getVariables(environment);
  console.log(
    JSON.stringify({
      case: "first_environment_read_after_integration_deletion",
      actual: "allow",
      variables_released: variables.length > 0 ? "yes" : "no",
      token_requests_total: tokenRequests,
      result: "unexpected",
    }),
  );
  process.exitCode = 2;
} catch (error) {
  console.log(
    JSON.stringify({
      case: "first_environment_read_after_integration_deletion",
      actual: "deny",
      variables_released: "no",
      token_requests_total: tokenRequests,
      result: "expected",
      error: String(error?.message ?? error).slice(0, 200),
    }),
  );
}
