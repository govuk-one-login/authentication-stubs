import {
  DecodedRequest,
  DecodedStorageAccessToken,
  EncodedUserInfoClaim,
} from "./types";
import { compactVerify, KeyLike } from "jose";
import process from "node:process";
import { processJoseError } from "./error-helper";
import { getPublicSigningKey } from "./jwks-helper";

export async function validateAuthorisationJwt(
  nestedJws: string
): Promise<DecodedRequest | string> {
  const publicJwk = await getPublicSigningKey(
    nestedJws,
    process.env.AUTH_IPV_PUBLIC_SIGNING_KEY_JWKS_ENDPOINT,
    process.env.AUTH_PUBLIC_SIGNING_KEY_IPV
  );
  const authoriseRequestAsJson = await verifyAndDecodeJwt<DecodedRequest>(
    nestedJws,
    publicJwk
  );

  const validationError = validatePayloadFields(authoriseRequestAsJson);
  if (validationError) return validationError;

  return await processStorageAccessToken(authoriseRequestAsJson);
}

async function verifyAndDecodeJwt<T>(
  jws: string,
  publicJwk: KeyLike
): Promise<T> {
  let payload;
  try {
    ({ payload } = await compactVerify(jws, publicJwk));
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

async function validateStorageAccessTokenJWT(
  userInfo: EncodedUserInfoClaim
): Promise<DecodedStorageAccessToken | string> {
  const hasAccessTokenValues =
    userInfo["https://vocab.account.gov.uk/v1/storageAccessToken"]?.values !=
    undefined;

  if (hasAccessTokenValues) {
    const storageTokenJws =
      userInfo["https://vocab.account.gov.uk/v1/storageAccessToken"].values[0];

    const authSignaturePublicKey = await getPublicSigningKey(
      storageTokenJws,
      process.env.AUTH_IPV_STORAGE_TOKEN_SIGNING_KEY_JWKS_ENDPOINT,
      process.env.AUTH_PUBLIC_SIGNING_KEY_EVCS
    );
    const decodedPayloadAsJson =
      await verifyAndDecodeJwt<DecodedStorageAccessToken>(
        storageTokenJws,
        authSignaturePublicKey
      );

    try {
      if (decodedPayloadAsJson.scope !== "reverification") {
        return "Storage access token scope is not reverification";
      }
      return decodedPayloadAsJson;
    } catch (_e) {
      return "Storage access token payload is not valid json";
    }
  } else return "Storage access token does not contain values field";
}
