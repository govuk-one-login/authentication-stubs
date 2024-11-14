import { CompactEncrypt, importSPKI } from "jose";

//This is the public key equivalent of the local private key in parameters.
// Both have been committed deliberately to allow for local running and testing.
const publicKeyPem = `-----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApflLYqZm5IawLAHYtWoU
  vKdO7cFBmDIOASlGgGCEG0PVBC4FJH2pM3FUw72n7YTS+H73Y8ZfTNIgu9K7zxEa
  mCwimUAKU8Lsjq6Pqa0pZr2rE4l2MfO2j91uCcdlTzdM0kOkwcbzwqEdbDU+FJ4x
  FT5aaOWyuN/BKFsc5kNz2t4+OaeRu/ev3h7WCqh2MMW5PWDbR2lBnKZR8HvuXZc5
  ay0dUx098UjkLEBHIyT3FfzhXFMF2ZdOSysDMa64KwqeAWs6tjwM9+Bp3DYLkTsx
  BML/eqgIwdZI5QBCTxD8YC2oxC1obMspiAoEz05wt8cYscmT4rZAdBGMspuxNqo4
  6wIDAQAB
  -----END PUBLIC KEY-----`;

const base64Encode = (s) => {
  return Buffer.from(s, "utf-8").toString("base64");
};

const createJwt = (header, payload, signature) => {
  return [header, payload, signature]
    .map((e) => base64Encode(JSON.stringify(e)))
    .join(".");
};

const createUserInfoClaims = () => {
  const storageAccessTokenSignature = {
    sig: "a-storage-access-token-signature",
  };

  const storageAccessTokenAlgorithm = { alg: "some-storage-access-alg" };
  const storageAccessTokenPayload = {
    scope: "reverification",
    aud: [
      "https://credential-store.test.account.gov.uk",
      "https://identity.test.account.gov.uk",
    ],
    sub: "someSub",
    iss: "https://oidc.test.account.gov.uk/",
    exp: 1709051163,
    iat: 1709047563,
    jti: "dfccf751-be55-4df4-aa3f-a993193d5216",
  };
  return {
    userinfo: {
      "https://vocab.account.gov.uk/v1/storageAccessToken": {
        values: [
          createJwt(
            storageAccessTokenAlgorithm,
            storageAccessTokenPayload,
            storageAccessTokenSignature
          ),
        ],
      },
    },
  };
};

const createRequestJwt = () => {
  const algorithm = { alg: "some-alg" };
  const payload = { scope: "reverification", claims: createUserInfoClaims(), state: "test-state" };
  const signature = { sig: "a-signature" };

  return createJwt(algorithm, payload, signature);
};

(async () => {
  const dataToEncrypt = Uint8Array.from(createRequestJwt(), (c) =>
    c.charCodeAt(0)
  );

  const publicKey = await importSPKI(publicKeyPem, "RSA-OAEP-256");

  const encryptedRequest = await new CompactEncrypt(dataToEncrypt)
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(publicKey);

  console.log(`Encrypted request:\n------\n${encryptedRequest}`);
})();
