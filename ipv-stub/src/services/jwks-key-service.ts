import { KeyLike, importJWK, importSPKI } from "jose";
import { CodedError } from "../helper/result-helper";
import { logger } from "../helper/logger";

export interface JwksResponse {
  keys: Array<{
    kid?: string;
    kty: string;
    use?: string;
    alg?: string;
    [key: string]: unknown;
  }>;
}

export enum KeyType {
  IPV = "IPV",
  EVCS = "EVCS",
}

export class JwksKeyService {
  private static async fetchJwks(jwksUri: string): Promise<JwksResponse> {
    const response = await fetch(jwksUri);
    if (!response.ok) {
      throw new CodedError(500, `Failed to fetch JWKS: ${response.statusText}`);
    }
    return await response.json();
  }

  private static getEnvironmentKey(keyType: KeyType): string | undefined {
    switch (keyType) {
      case KeyType.IPV:
        return process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
      case KeyType.EVCS:
        return process.env.AUTH_PUBLIC_SIGNING_KEY_EVCS;
    }
  }

  private static getJwksEndpoint(keyType: KeyType): string | undefined {
    switch (keyType) {
      case KeyType.IPV:
        return process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT;
      case KeyType.EVCS:
        return process.env.AUTH_EVCS_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT;
    }
  }

  public static async getSigningKey(
    keyType: KeyType,
    kid?: string
  ): Promise<KeyLike> {
    // Check for environment variable override first
    const envKey = this.getEnvironmentKey(keyType);
    if (envKey) {
      logger.info(`Using environment variable override for ${keyType} key`);
      return await importSPKI(envKey, "ES256");
    }

    // Try JWKS endpoint
    const jwksUri = this.getJwksEndpoint(keyType);
    if (jwksUri) {
      try {
        const jwks = await this.fetchJwks(jwksUri);
        
        // If kid is provided, look for specific key
        if (kid) {
          for (const k of jwks.keys) {
            if (k.kid === kid) {
              logger.info(`Using JWKS key with kid: ${kid} for ${keyType}`);
              return (await importJWK(k)) as KeyLike;
            }
          }
          throw new CodedError(400, `Key not found in JWKS for kid: ${kid}`);
        }

        // If no kid, use first available key
        if (jwks.keys.length > 0) {
          logger.info(`Using first available JWKS key for ${keyType}`);
          return (await importJWK(jwks.keys[0])) as KeyLike;
        }

        throw new CodedError(500, `No keys found in JWKS for ${keyType}`);
      } catch (error) {
        logger.warn(`JWKS fetch failed for ${keyType}, checking fallback: ${error}`);
      }
    }

    throw new CodedError(500, `No signing key available for ${keyType}`);
  }
}