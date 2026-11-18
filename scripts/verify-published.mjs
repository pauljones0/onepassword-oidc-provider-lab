#!/usr/bin/env node

const issuer = "https://pauljones0.github.io/onepassword-oidc-provider-lab";
const configuration = await fetch(`${issuer}/.well-known/openid-configuration`).then((response) => {
  if (!response.ok) throw new Error(`discovery returned ${response.status}`);
  return response.json();
});
const jwks = await fetch(configuration.jwks_uri).then((response) => {
  if (!response.ok) throw new Error(`JWKS returned ${response.status}`);
  return response.json();
});

if (configuration.issuer !== issuer) throw new Error("issuer mismatch");
if (!jwks.keys?.some((key) => key.kid === "lab-rs256-v1")) throw new Error("lab key missing");

console.log(JSON.stringify({ issuer: configuration.issuer, jwks_uri: configuration.jwks_uri, key_ids: jwks.keys.map((key) => key.kid) }));

