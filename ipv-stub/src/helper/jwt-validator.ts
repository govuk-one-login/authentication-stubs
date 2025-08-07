import {
  DecodedRequest,
  DecodedStorageAccessToken,
  EncodedUserInfoClaim,
} from "./types";
import {
  KeyLike,
  compactVerify,
  importJWK,
  importSPKI,
  decodeProtectedHeader,
} from "jose";
import { CodedError } from "./result-helper";
import process from "node:process";
import { processJoseError } from "./error-helper";
import { logger } from "./logger";

export async function validateAuthorisationJwt(
  nestedJws: string
): Promise<DecodedRequest | string> {
  const publicJwk = await getPublicSigningKey(nestedJws);
  const authoriseRequestAsJson = await verifyAndDecodeJwt(nestedJws, publicJwk);

  const validationError = validatePayloadFields(authoriseRequestAsJson);
  if (validationError) return validationError;

  return await processStorageAccessToken(authoriseRequestAsJson);
}

async function getPublicSigningKey(nestedJws: string): Promise<KeyLike> {
  const header = decodeProtectedHeader(nestedJws);
  const kid = header.kid;

  if (kid) {
    logger.info("kid received in decoded protected header");
    return await getPublicKeyFromJwks(kid);
  }

  const authSignaturePublicKeyIpv = process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
  if (!authSignaturePublicKeyIpv) {
    throw new CodedError(500, "Auth IPV signing public key not found");
  }
  return await importSPKI(authSignaturePublicKeyIpv, "ES256");
}

async function getPublicKeyFromJwks(kid: string): Promise<KeyLike> {
  const jwksUri = process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT;
  if (!jwksUri) {
    throw new CodedError(500, "JWKS URI not found");
  }

  const jwks = await fetchJwks(jwksUri);
  for (const k of jwks.keys) {
    if (k.kid === kid) {
      logger.info(`using kid: ${kid}`);
      return (await importJWK(k)) as KeyLike;
    }
  }

  throw new CodedError(400, "Key not found in JWKS for provided kid");
}

async function verifyAndDecodeJwt(
  nestedJws: string,
  publicJwk: KeyLike
): Promise<DecodedRequest> {
  let payload;
  try {
    ({ payload } = await compactVerify(nestedJws, publicJwk));
  } catch (error) {
    processJoseError(error);
  }

  const decodedPayload = new TextDecoder().decode(payload);
  return JSON.parse(decodedPayload);
}

function validatePayloadFields(
  authoriseRequestAsJson: DecodedRequest
): string | null {
  if (authoriseRequestAsJson.scope !== "reverification") {
    return "Scope in request payload must be reverification";
  }
  if (authoriseRequestAsJson.state === undefined) {
    return "Payload must contain state";
  }
  if (authoriseRequestAsJson.sub === undefined) {
    return "Payload must contain sub";
  }
  if (!authoriseRequestAsJson.claims?.userinfo) {
    return "Request payload is missing user info claim";
  }
  return null;
}

async function processStorageAccessToken(
  authoriseRequestAsJson: DecodedRequest
) {
  const userinfo = authoriseRequestAsJson.claims
    .userinfo as unknown as EncodedUserInfoClaim;
  const storageAccessTokenJWTOrErrorString =
    await validateStorageAccessTokenJWT(userinfo);

  if (typeof storageAccessTokenJWTOrErrorString === "string") {
    return storageAccessTokenJWTOrErrorString;
  }

  const storageAccessTokenClaimName =
    "https://vocab.account.gov.uk/v1/storageAccessToken";
  (authoriseRequestAsJson.claims.userinfo as Record<string, unknown>)[
    storageAccessTokenClaimName
  ] = {
    values: [storageAccessTokenJWTOrErrorString],
  };

  return authoriseRequestAsJson;
}

async function fetchJwks(jwksUri: string) {
  const response = await fetch(jwksUri);
  if (!response.ok) {
    throw new CodedError(500, `Failed to fetch JWKS: ${response.statusText}`);
  }
  return await response.json();
}

async function validateStorageAccessTokenJWT(
  userInfo: EncodedUserInfoClaim
): Promise<DecodedStorageAccessToken | string> {
  const hasAccessTokenValues =
    userInfo["https://vocab.account.gov.uk/v1/storageAccessToken"]?.values !=
    undefined;

  let payload;
  let decodedPayloadAsJson;

  if (hasAccessTokenValues) {
    const storageTokenJws =
      userInfo["https://vocab.account.gov.uk/v1/storageAccessToken"].values[0];

    const authSignaturePublicKey = process.env.AUTH_PUBLIC_SIGNING_KEY_EVCS;
    if (!authSignaturePublicKey) {
      throw new CodedError(500, "Auth EVCS signing public key not found");
    }

    const publicJwk = await importSPKI(authSignaturePublicKey, "ES256");
    try {
      ({ payload } = await compactVerify(storageTokenJws, publicJwk));
      const textDecoder = new TextDecoder();
      decodedPayloadAsJson = JSON.parse(textDecoder.decode(payload));
    } catch (error) {
      processJoseError(error);
    }

    try {
      if (decodedPayloadAsJson.scope !== "reverification") {
        return "Storage access token scope is not reverification";
      }

      return decodedPayloadAsJson as DecodedStorageAccessToken;
    } catch (_e) {
      return "Storage access token payload is not valid json";
    }
  } else return "Storage access token does not contain values field";
}
