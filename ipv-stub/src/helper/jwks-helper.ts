import { importJWK, KeyLike } from "jose";
import * as jose from "jose";
import { CodedError } from "./result-helper";
import { logger } from "./logger";

export async function getPublicSigningKey(jws: string, jwksUri?: string): Promise<KeyLike> {
  const header = jose.decodeProtectedHeader(jws);
  const kid = header.kid;

  if (!kid) {
    throw new CodedError(500, "kid not found in decoded protected header");
  }

  if (!jwksUri) {
    throw new CodedError(500, "JWKS URI not found");
  }

  return await getPublicKeyFromJwks(kid, jwksUri);
}

async function getPublicKeyFromJwks(kid: string, jwksUri: string): Promise<KeyLike> {
  const jwks = await fetchJwks(jwksUri);
  for (const k of jwks.keys) {
    if (k.kid === kid) {
      logger.info(`using kid: ${kid}`);
      return (await importJWK(k)) as KeyLike;
    }
  }

  throw new CodedError(400, "Key not found in JWKS for provided kid");
}

async function fetchJwks(jwksUri: string) {
  const response = await fetch(jwksUri);
  if (!response.ok) {
    throw new CodedError(500, `Failed to fetch JWKS: ${response.statusText}`);
  }
  return await response.json();
}