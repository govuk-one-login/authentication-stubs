import { getPublicSigningKey } from "./jwks-helper.ts";
import { jwtVerify } from "jose";
import { CompositePayload } from "../types/types.ts";

async function validateAccessToken(accessTokenJWT: string) {
  const publicSigningKeyAuthAudience = await getPublicSigningKey(
    accessTokenJWT,
    undefined,
    process.env.AUTH_PUBLIC_SIGNING_KEY_AUTH_AUDIENCE
  );

  return await jwtVerify(accessTokenJWT, publicSigningKeyAuthAudience);
}

async function validateClientAssertionJWT(clientAssertionJWT: string) {
  const publicSigningKeyAMCAudience = await getPublicSigningKey(
    clientAssertionJWT,
    undefined,
    process.env.AUTH_PUBLIC_SIGNING_KEY_AMC_AUDIENCE
  );

  return await jwtVerify(clientAssertionJWT, publicSigningKeyAMCAudience);
}

export async function validateCompositeJWT(
  compositeJWT: string
): Promise<{ payload: CompositePayload }> {
  const {
    payload: clientAssertionPayload,
    protectedHeader: clientAssertionHeader,
  } = await validateClientAssertionJWT(compositeJWT);

  if (clientAssertionHeader.typ !== "JWT") {
    throw new Error("typ must be 'JWT'");
  }

  if (clientAssertionHeader.alg !== "ES256") {
    throw new Error("alg must be ES256");
  }

  if (typeof clientAssertionPayload.access_token !== "string") {
    throw new TypeError("access_token must be a string");
  }

  const { payload: accessTokenPayload, protectedHeader: accessTokenHeader } =
    await validateAccessToken(clientAssertionPayload.access_token);

  if (accessTokenHeader.typ !== "at+jwt") {
    throw new Error("typ must be 'at+jwt'");
  }

  return {
    payload: {
      ...clientAssertionPayload,
      access_token: accessTokenPayload,
    } as CompositePayload,
  };
}
