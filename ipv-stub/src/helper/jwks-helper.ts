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
  try {
    logger.info(`Fetching JWKS from: ${jwksUri}`);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

    const response = await fetch(jwksUri, {
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "User-Agent": "ipv-stub/1.0.0",
      },
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      logger.error(
        `JWKS fetch failed with status: ${response.status} ${response.statusText}`
      );
      throw new CodedError(
        500,
        `Failed to fetch JWKS: ${response.status} ${response.statusText}`
      );
    }

    const jwks = await response.json();
    logger.info(
      `Successfully fetched JWKS with ${jwks.keys?.length || 0} keys`
    );
    return jwks;
  } catch (error) {
    if (error instanceof CodedError) {
      throw error;
    }

    logger.error(`JWKS fetch error: ${error}`);

    if (error instanceof Error) {
      if (error.name === "AbortError") {
        throw new CodedError(500, "JWKS fetch timeout - endpoint unreachable");
      }
      if (error.message.includes("fetch failed")) {
        throw new CodedError(
          500,
          `Network error fetching JWKS from ${jwksUri}: ${error.message}`
        );
      }
    }

    throw new CodedError(500, `Unexpected error fetching JWKS: ${error}`);
  }
}

async function getPublicKeyFromBackup(backupSigningKey?: string) {
  if (!backupSigningKey) {
    throw new CodedError(500, "Public signing key not found");
  }
  logger.info("Using backup signing key from env variables");
  return await importSPKI(backupSigningKey, "ES256");
}
