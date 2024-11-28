import {
  DecodedRequest,
  DecodedStorageAccessToken,
  EncodedUserInfoClaim,
} from "./types.ts";

export function parseRequest(jwtString: string): DecodedRequest | string {
  const jwtAsJson = JSON.parse(jwtString);

  if (jwtAsJson.scope !== "reverification") {
    return "Scope in request payload must be verification";
  }
  if (jwtAsJson.state === undefined) {
    return "Payload must contain state";
  }
  if (jwtAsJson.sub === undefined) {
    return "Payload must contain sub";
  }
  const hasUserInfoClaim = jwtAsJson.claims?.userinfo != undefined;

  if (!hasUserInfoClaim) {
    return "Request payload is missing user info claim";
  }

  const parsedUserInfoClaimOrErrorString = parseStorageAccessToken(
    jwtAsJson.claims.userinfo
  );
  if (typeof parsedUserInfoClaimOrErrorString === "string") {
    return parsedUserInfoClaimOrErrorString;
  } else {
    return {
      sub: jwtAsJson.sub,
      scope: "reverification",
      state: jwtAsJson.state,
      claims: {
        userinfo: {
          "https://vocab.account.gov.uk/v1/storageAccessToken": {
            values: [parsedUserInfoClaimOrErrorString],
          },
        },
      },
    };
  }
}

function parseStorageAccessToken(
  userInfo: EncodedUserInfoClaim
): DecodedStorageAccessToken | string {
  const hasAccessTokenValues =
    userInfo["https://vocab.account.gov.uk/v1/storageAccessToken"]?.values !=
    undefined;
  if (hasAccessTokenValues) {
    const parts =
      userInfo[
        "https://vocab.account.gov.uk/v1/storageAccessToken"
      ].values[0].split(".");

    if (parts.length !== 3) {
      return "Storage access token is not a valid jwt (does not contain three parts)";
    }

    //TODO: need to validate the signature, that to follow this PR
    const [_decodedHeader, decodedPayload, _decodedSignature] = parts.map(
      (part) => Buffer.from(part, "base64url").toString("utf8")
    );

    try {
      const payloadAsJson = JSON.parse(decodedPayload);
      if (payloadAsJson.scope !== "reverification") {
        return "Storage access token scope is not reverification";
      }

      return payloadAsJson as DecodedStorageAccessToken;
    } catch (_e) {
      return "Storage access token payload is not valid json";
    }
  } else return "Storage access token does not contain values field";
}
