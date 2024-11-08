export function isValidRequest(requestString: string): boolean {
  const requestAsJson = JSON.parse(requestString);

  const hasUserInfoClaim = requestAsJson.claims?.userinfo != undefined;
  return (
    requestAsJson["scope"] === "reverification" &&
    hasUserInfoClaim &&
    validateUserInfoClaim(requestAsJson.claims.userinfo)
  );
}

type EncodedUserInfoClaim = {
  "https://vocab.account.gov.uk/v1/storageAccessToken": {
    values: string;
  };
};

function validateUserInfoClaim(userInfo: EncodedUserInfoClaim): boolean {
  const hasAccessTokenValues =
    userInfo["https://vocab.account.gov.uk/v1/storageAccessToken"]?.values !=
    undefined;
  if (hasAccessTokenValues) {
    const parts =
      userInfo[
        "https://vocab.account.gov.uk/v1/storageAccessToken"
      ].values[0].split(".");

    if (parts.length !== 3) {
      return false;
    }

    //TODO: need to validate the signature, that to follow this PR
    const [_decodedHeader, decodedPayload, _decodedSignature] = parts.map(
      (part) => Buffer.from(part, "base64url").toString("utf8")
    );

    try {
      const payloadAsJson = JSON.parse(decodedPayload);

      return payloadAsJson.scope === "reverification";
    } catch (e) {
      return false;
    }
  } else return false;
}
