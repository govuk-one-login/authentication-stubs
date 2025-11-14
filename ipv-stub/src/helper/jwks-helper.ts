import { decodeProtectedHeader, importJWK, importSPKI, KeyLike } from "jose";
import { CodedError } from "./result-helper";
import { logger } from "./logger";

export async function getPublicSigningKey(
  jws: string,
  jwksUri?: string,
  backupSigningKey?: string
): Promise<KeyLike> {
  const header = decodeProtectedHeader(jws);
  const kid = header.kid;

  if (!kid || !jwksUri) {
    if (!kid) logger.info("kid not found in decoded protected header");
    if (!jwksUri) logger.info("JWKS URI not found");
    return await getPublicKeyFromBackup(backupSigningKey);
  }

  return await getPublicKeyFromJwks(kid, jwksUri);
}

async function getPublicKeyFromJwks(
  kid: string,
  jwksUri: string
): Promise<KeyLike> {
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

async function getPublicKeyFromBackup(backupSigningKey?: string) {
  if (!backupSigningKey) {
    throw new CodedError(500, "Public signing public key not found");
  }
  logger.info("Using backup signing key from env variables");
  return await importSPKI(backupSigningKey, "ES256");
}
