#!/usr/bin/env node

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const issuer = "https://pauljones0.github.io/onepassword-oidc-provider-lab";

function getArg(name, fallback) {
  const index = process.argv.indexOf(`--${name}`);
  return index === -1 ? fallback : process.argv[index + 1];
}

function hasArg(name) {
  return process.argv.includes(`--${name}`);
}

function b64url(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(value);
  return bytes.toString("base64url");
}

const now = Math.floor(Date.now() / 1000);
const alg = getArg("alg", "RS256");
const header = {
  alg,
  kid: getArg("kid", "lab-rs256-v1"),
  typ: "JWT",
};

for (const field of ["jku", "x5u"]) {
  const value = getArg(field);
  if (value) header[field] = value;
}

const payload = {
  iss: getArg("iss", issuer),
  sub: getArg("sub", "lab:workload:baseline"),
  aud: getArg("aud", "onepassword-lab"),
  iat: now + Number(getArg("iat-offset", "0")),
  nbf: now + Number(getArg("nbf-offset", "-5")),
  exp: now + Number(getArg("exp-offset", "300")),
  lab: "onepassword-authorized-research",
  role: getArg("role", "baseline"),
  nonce: crypto.randomUUID(),
};

if (hasArg("omit-aud")) delete payload.aud;
if (hasArg("omit-exp")) delete payload.exp;
if (hasArg("aud-array")) payload.aud = String(payload.aud).split(",");

const encodedHeader = b64url(JSON.stringify(header));
const encodedPayload = b64url(JSON.stringify(payload));
const signingInput = `${encodedHeader}.${encodedPayload}`;

let signature = "";
if (alg === "RS256") {
  const privateKey = fs.readFileSync(path.join(root, ".lab-private-key.pem"));
  signature = b64url(crypto.sign("RSA-SHA256", Buffer.from(signingInput), privateKey));
} else if (alg === "HS256") {
  const publicKey = fs.readFileSync(path.join(root, ".lab-public-key.pem"));
  signature = b64url(crypto.createHmac("sha256", publicKey).update(signingInput).digest());
} else if (alg !== "none") {
  throw new Error(`Unsupported lab algorithm: ${alg}`);
}

process.stdout.write(`${signingInput}.${signature}\n`);

