import {
  DecodedRequest,
  DecodedStorageAccessToken,
  EncodedUserInfoClaim,
} from "./types";
import * as jose from "jose";
import { CodedError } from "./result-helper";
import process from "node:process";
import { processJoseError } from "./error-helper";

export async function validateAuthorisationJwt(
  nestedJws: string
): Promise<DecodedRequest | string> {
  const authSignaturePublicKeyIpv = process.env.AUTH_PUBLIC_SIGNING_KEY_IPV;
  if (!authSignaturePublicKeyIpv) {
    throw new CodedError(500, "Auth IPV signing public key not found");
  }

  const publicJwk = await jose.importSPKI(authSignaturePublicKeyIpv, "ES256");

  let payload;
  try {
    ({ payload } = await jose.compactVerify(nestedJws, publicJwk));
  } catch (error) {
    processJoseError(error);
  }

  const decodedPayload = new TextDecoder().decode(payload);

  const authoriseRequestAsJson = JSON.parse(decodedPayload);

  if (authoriseRequestAsJson.scope !== "reverification") {
    return "Scope in request payload must be reverification";
  }
  if (authoriseRequestAsJson.state === undefined) {
    return "Payload must contain state";
  }
  if (authoriseRequestAsJson.sub === undefined) {
    return "Payload must contain sub";
  }
  const hasUserInfoClaim = authoriseRequestAsJson.claims?.userinfo != undefined;

  if (!hasUserInfoClaim) {
    return "Request payload is missing user info claim";
  }

  const storageAccessTokenJWTOrErrorString =
    await validateStorageAccessTokenJWT(authoriseRequestAsJson.claims.userinfo);

  if (typeof storageAccessTokenJWTOrErrorString === "string") {
    return storageAccessTokenJWTOrErrorString;
  } else {
    const storageAccessTokenClaimName =
      "https://vocab.account.gov.uk/v1/storageAccessToken";

    authoriseRequestAsJson.claims.userinfo[storageAccessTokenClaimName] = {
      values: [],
    };
    authoriseRequestAsJson.claims.userinfo[
      storageAccessTokenClaimName
    ].values.push(storageAccessTokenJWTOrErrorString);
    return authoriseRequestAsJson;
  }
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

    const publicJwk = await jose.importSPKI(authSignaturePublicKey, "ES256");
    try {
      ({ payload: payload } = await jose.compactVerify(
        storageTokenJws,
        publicJwk
      ));
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
