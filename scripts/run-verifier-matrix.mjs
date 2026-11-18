#!/usr/bin/env node

import { createClient } from "@1password/sdk";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const issuer = process.env.OIDC_ISSUER ?? "https://onepassword-oidc-provider-lab.vercel.app";
const untrustedJwks = `${issuer}/untrusted-jwks.json`;
const workloadUuid = process.env.OP_WORKLOAD_ID;
const environmentId = process.env.OP_ENVIRONMENT_ID;
// SDK core 0.5 expects the documented `ops_` wrapper without base64 padding.
const customerManagedSecret = process.env.OP_INTEGRATION_KEY?.replace(/=+$/, "");
const traceFailures = process.env.OP_MATRIX_TRACE === "1";
const caseFilter = process.env.OP_MATRIX_CASE;
const requestTimeoutMs = Number(process.env.OP_MATRIX_TIMEOUT_MS ?? 20000);

// Bound every SDK request so a broker/network stall cannot freeze a matrix run
// and silently erase the distinction between a verifier decision and no result.
const nativeFetch = globalThis.fetch;
globalThis.fetch = async (input, init = {}) => {
  const timeoutSignal = AbortSignal.timeout(requestTimeoutMs);
  const signal = init.signal ? AbortSignal.any([init.signal, timeoutSignal]) : timeoutSignal;
  const response = await nativeFetch(input, { ...init, signal });
  if (traceFailures && !response.ok) {
    const url = typeof input === "string" ? input : input?.url;
    const responseText = (await response.clone().text())
      .replace(/ops_[A-Za-z0-9+/_=-]+/g, "<redacted-integration-key>")
      .replace(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "<redacted-jwt>")
      .slice(0, 1000);
    console.error(JSON.stringify({ trace: "http_failure", url, status: response.status, body: responseText }));
  }
  return response;
};

if (!workloadUuid || !environmentId || !customerManagedSecret) {
  throw new Error("Set OP_WORKLOAD_ID, OP_ENVIRONMENT_ID, and OP_INTEGRATION_KEY");
}

const trustedPrivateKey = fs.readFileSync(path.join(root, ".lab-private-key.pem"));
const trustedPublicKey = fs.readFileSync(path.join(root, ".lab-public-key.pem"));
const attackerPrivateKey = fs.readFileSync(path.join(root, ".lab-attacker-private-key.pem"));
const attackerPublicJwk = crypto.createPublicKey(attackerPrivateKey).export({ format: "jwk" });

function b64url(value) {
  return Buffer.from(value).toString("base64url");
}

function tokenFor(audience, options = {}) {
  const now = Math.floor(Date.now() / 1000);
  const alg = options.alg ?? "RS256";
  const signingAlg = options.signingAlg ?? alg;
  const header = {
    alg,
    typ: "JWT",
    ...(options.omitKid ? {} : { kid: options.kid ?? "lab-rs256-v1" }),
    ...(options.jku ? { jku: options.jku } : {}),
    ...(options.x5u ? { x5u: options.x5u } : {}),
    ...(options.header ?? {}),
  };
  const payload = {
    iss: options.iss ?? issuer,
    sub: options.sub ?? "lab:workload:baseline",
    aud: options.aud ?? audience,
    iat: now,
    nbf: options.nbf ?? now - 5,
    exp: options.exp ?? now + 300,
    jti: crypto.randomUUID(),
    lab: "onepassword-authorized-research",
    role: options.role ?? "baseline",
    nonce: crypto.randomUUID(),
    ...(options.payload ?? {}),
  };
  if (options.omitAud) delete payload.aud;
  if (options.omitExp) delete payload.exp;
  if (options.omitRole) delete payload.role;

  const headerJson = options.headerJson ? options.headerJson(header) : JSON.stringify(header);
  const encodedHeader = b64url(headerJson);
  const payloadJson = options.payloadJson ? options.payloadJson(payload) : JSON.stringify(payload);
  // RFC 7797 compact JWS requires an unencoded payload to contain no literal
  // periods. JSON unicode escapes preserve the parsed claim values while
  // keeping the compact serialization structurally unambiguous.
  const encodedPayload = options.unencodedPayload ? payloadJson.replaceAll(".", "\\u002e") : b64url(payloadJson);
  const input = `${encodedHeader}.${encodedPayload}`;
  let signature = "";
  if (signingAlg === "RS256") {
    signature = crypto
      .sign("RSA-SHA256", Buffer.from(input), options.attackerKey ? attackerPrivateKey : trustedPrivateKey)
      .toString("base64url");
  } else if (signingAlg === "HS256") {
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
  {
    name: "multi_audience_attacker_azp",
    expect: "deny",
    makeOptions: (aud) => ({ aud: [aud, "attacker-client"], payload: { azp: "attacker-client" } }),
  },
  {
    name: "multi_audience_attacker_first_azp",
    expect: "deny",
    makeOptions: (aud) => ({ aud: ["attacker-client", aud], payload: { azp: "attacker-client" } }),
  },
  {
    name: "single_expected_audience_attacker_azp",
    expect: "deny",
    makeOptions: (aud) => ({ aud, payload: { azp: "attacker-client" } }),
  },
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
  { name: "required_claim_case_variant", expect: "deny", options: { role: "Baseline" } },
  { name: "required_claim_trailing_space", expect: "deny", options: { role: "baseline " } },
  { name: "required_claim_null_byte_suffix", expect: "deny", options: { role: "baseline\u0000untrusted" } },
  { name: "required_claim_boolean", expect: "deny", options: { payload: { role: true } } },
  { name: "required_claim_number", expect: "deny", options: { payload: { role: 1 } } },
  { name: "required_claim_object", expect: "deny", options: { payload: { role: { value: "baseline" } } } },
  { name: "audience_number", expect: "deny", options: { payload: { aud: 1 } } },
  { name: "audience_object", expect: "deny", options: { payload: { aud: { value: "placeholder" } } } },
  { name: "issuer_trailing_slash", expect: "deny", options: { iss: `${issuer}/` } },
  { name: "expiry_string", expect: "deny", makeOptions: () => ({ payload: { exp: String(now() + 300) } }) },
  { name: "expired_numeric_string", expect: "deny", makeOptions: () => ({ payload: { exp: String(now() - 30) } }) },
  { name: "expiry_nonnumeric_string", expect: "deny", options: { payload: { exp: "not-a-number" } } },
  { name: "expiry_empty_string", expect: "deny", options: { payload: { exp: "" } } },
  { name: "expiry_boolean", expect: "deny", options: { payload: { exp: true } } },
  { name: "expiry_object", expect: "deny", options: { payload: { exp: { value: 4102444800 } } } },
  { name: "future_nbf_numeric_string", expect: "deny", makeOptions: () => ({ payload: { nbf: String(now() + 300) } }) },
  { name: "nbf_nonnumeric_string", expect: "deny", options: { payload: { nbf: "not-a-number" } } },
  {
    name: "unknown_critical_header",
    expect: "deny",
    options: { header: { crit: ["research-extension"], "research-extension": true } },
  },
  {
    name: "b64_false_but_encoded_payload",
    expect: "deny",
    options: { header: { b64: false, crit: ["b64"] } },
  },
  {
    name: "b64_false_unencoded_payload",
    expect: "deny",
    options: { header: { b64: false, crit: ["b64"] }, unencodedPayload: true },
  },
  {
    name: "duplicate_alg_none_then_rs256",
    expect: "deny",
    options: {
      headerJson: (header) => JSON.stringify(header).replace('"alg":"RS256"', '"alg":"none","alg":"RS256"'),
    },
  },
  {
    name: "duplicate_alg_rs256_then_none",
    expect: "deny",
    options: {
      headerJson: (header) => JSON.stringify(header).replace('"alg":"RS256"', '"alg":"RS256","alg":"none"'),
    },
  },
  {
    name: "duplicate_alg_rs256_then_hs256_hmac_signature",
    expect: "deny",
    options: {
      alg: "HS256",
      headerJson: (header) => JSON.stringify(header).replace('"alg":"HS256"', '"alg":"RS256","alg":"HS256"'),
    },
  },
  {
    name: "duplicate_alg_hs256_then_rs256_hmac_signature",
    expect: "deny",
    options: {
      alg: "HS256",
      headerJson: (header) => JSON.stringify(header).replace('"alg":"HS256"', '"alg":"HS256","alg":"RS256"'),
    },
  },
  {
    name: "duplicate_alg_rs256_then_none_unsigned",
    expect: "deny",
    options: {
      signingAlg: "none",
      headerJson: (header) => JSON.stringify(header).replace('"alg":"RS256"', '"alg":"RS256","alg":"none"'),
    },
  },
  {
    name: "duplicate_alg_none_then_rs256_unsigned",
    expect: "deny",
    options: {
      signingAlg: "none",
      headerJson: (header) => JSON.stringify(header).replace('"alg":"RS256"', '"alg":"none","alg":"RS256"'),
    },
  },
  {
    name: "embedded_untrusted_jwk",
    expect: "deny",
    options: { attackerKey: true, header: { jwk: attackerPublicJwk } },
  },
  {
    name: "duplicate_role_untrusted_then_baseline",
    expect: "deny",
    options: {
      payloadJson: (payload) =>
        JSON.stringify(payload).replace('"role":"baseline"', '"role":"untrusted","role":"baseline"'),
    },
  },
  {
    name: "duplicate_role_baseline_then_untrusted",
    expect: "deny",
    options: {
      payloadJson: (payload) =>
        JSON.stringify(payload).replace('"role":"baseline"', '"role":"baseline","role":"untrusted"'),
    },
  },
];

let unexpected = 0;
const selectedCases = caseFilter ? cases.filter((test) => test.name === caseFilter) : cases;
for (const test of selectedCases) {
  let actual = "allow";
  let variables = [];
  let diagnostic;
  try {
    const client = await createClient({
      integrationName: "1Password custom OIDC verifier research",
      integrationVersion: "1.0.0",
      oidcFetcher: async (audience) => tokenFor(audience, test.makeOptions?.(audience) ?? test.options),
      workloadDetails: { customerManagedSecret, workloadUuid },
    });
    const response = await client.environments.getVariables(environmentId);
    variables = response.variables;
  } catch (error) {
    actual = "deny";
    const clean = (value) =>
      String(value ?? "")
        .replace(/ops_[A-Za-z0-9+/_=-]+/g, "<redacted-integration-key>")
        .replace(/A3-[A-Z0-9-]+/g, "<redacted-secret-key>")
        .slice(0, 500);
    diagnostic = {
      name: clean(error?.name),
      message: clean(error?.message),
      cause_name: clean(error?.cause?.name),
      cause_message: clean(error?.cause?.message),
    };
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
      ...(result === "unexpected" ? { diagnostic } : {}),
    }),
  );
  await new Promise((resolve) => setTimeout(resolve, 500));
}

console.log(JSON.stringify({ summary: "custom_oidc_verifier_matrix", total: selectedCases.length, unexpected }));
if (unexpected > 0) process.exitCode = 2;

