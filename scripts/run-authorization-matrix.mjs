#!/usr/bin/env node

import { createClient } from "@1password/sdk";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const issuer = "https://onepassword-oidc-provider-lab.vercel.app";
const integrationKey = process.env.OP_INTEGRATION_KEY?.replace(/=+$/, "");
const baselineWorkload = process.env.OP_WORKLOAD_ID;
const baselineEnvironment = process.env.OP_ENVIRONMENT_ID;
const ungrantedEnvironment = process.env.OP_UNGRANTED_ENVIRONMENT_ID;
const privateKey = fs.readFileSync(path.join(root, ".lab-private-key.pem"));

if (!integrationKey || !baselineWorkload || !baselineEnvironment || !ungrantedEnvironment) {
  throw new Error(
    "Set OP_INTEGRATION_KEY, OP_WORKLOAD_ID, OP_ENVIRONMENT_ID, and OP_UNGRANTED_ENVIRONMENT_ID",
  );
}

const b64url = (value) => Buffer.from(value).toString("base64url");

function mintToken(audience, { jti = crypto.randomUUID() } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "RS256", typ: "JWT", kid: "lab-rs256-v1" };
  const payload = {
    iss: issuer,
    sub: "lab:workload:baseline",
    aud: audience,
    iat: now,
    nbf: now - 5,
    exp: now + 300,
    jti,
    nonce: crypto.randomUUID(),
    lab: "onepassword-authorized-research",
    role: "baseline",
  };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  const signature = crypto.sign("RSA-SHA256", Buffer.from(input), privateKey).toString("base64url");
  return `${input}.${signature}`;
}

async function authorize({ workload = baselineWorkload, environment = baselineEnvironment, fetchToken }) {
  try {
    const client = await createClient({
      integrationName: "Custom OIDC authz research",
      integrationVersion: "1.0.0",
      oidcFetcher: fetchToken ?? (async (audience) => mintToken(audience)),
      workloadDetails: { customerManagedSecret: integrationKey, workloadUuid: workload },
    });
    const { variables } = await client.environments.getVariables(environment);
    return { outcome: "allow", variablesReleased: variables.length > 0 ? "yes" : "no" };
  } catch (error) {
    return {
      outcome: "deny",
      variablesReleased: "no",
      error: String(error?.message ?? error).slice(0, 200),
    };
  }
}

const cases = [
  {
    name: "baseline_custom_workload_a1",
    expected: "allow",
    input: {},
  },
  {
    name: "custom_workload_ungranted_a2",
    expected: "deny",
    input: { environment: ungrantedEnvironment },
  },
  {
    name: "lowercase_custom_workload_id",
    expected: "deny",
    input: { workload: baselineWorkload.toLowerCase() },
  },
  {
    name: "unknown_workload_id",
    expected: "deny",
    input: { workload: "AAAAAAAAAAAAAAAAAAAAAAAAAA" },
  },
  {
    name: "github_workload_one_with_custom_provider_key",
    expected: "deny",
    input: { workload: "WBCXWVLWRJDGXBJBATYF35J6GM" },
  },
  {
    name: "github_workload_two_with_custom_provider_key",
    expected: "deny",
    input: { workload: "QCLLGFGDJJEBHDJMBEOSVDHV4Y" },
  },
];

let unexpected = 0;
for (const test of cases) {
  const result = await authorize(test.input);
  const verdict = result.outcome === test.expected ? "expected" : "unexpected";
  if (verdict === "unexpected") unexpected += 1;
  console.log(
    JSON.stringify({
      case: test.name,
      expected: test.expected,
      actual: result.outcome,
      result: verdict,
      variables_released: result.variablesReleased,
      ...(verdict === "unexpected" ? { error: result.error } : {}),
    }),
  );
}

let replayToken;
const firstReplay = await authorize({
  fetchToken: async (audience) => {
    replayToken = mintToken(audience);
    return replayToken;
  },
});
const secondReplay = await authorize({ fetchToken: async () => replayToken });
console.log(
  JSON.stringify({
    case: "exact_subject_token_replay",
    first: firstReplay.outcome,
    replay: secondReplay.outcome,
    replay_variables_released: secondReplay.variablesReleased,
    classification: secondReplay.outcome === "allow" ? "replay_accepted" : "replay_rejected",
  }),
);

let concurrentReplayToken;
const fetchConcurrentReplayToken = async (audience) => {
  concurrentReplayToken ??= mintToken(audience);
  return concurrentReplayToken;
};
const concurrentReplayResults = await Promise.all([
  authorize({ fetchToken: fetchConcurrentReplayToken }),
  authorize({ fetchToken: fetchConcurrentReplayToken }),
]);
const concurrentAllows = concurrentReplayResults.filter((result) => result.outcome === "allow").length;
const concurrentReplayVerdict = concurrentAllows <= 1 ? "expected" : "unexpected";
if (concurrentReplayVerdict === "unexpected") unexpected += 1;
console.log(
  JSON.stringify({
    case: "concurrent_exact_subject_token_replay",
    expected_maximum_allows: 1,
    actual_allows: concurrentAllows,
    result: concurrentReplayVerdict,
    variables_released_by: concurrentReplayResults.map((result) => result.variablesReleased),
  }),
);

console.log(JSON.stringify({ summary: "custom_oidc_authorization_matrix", total: cases.length + 2, unexpected }));
if (unexpected > 0) process.exitCode = 2;
