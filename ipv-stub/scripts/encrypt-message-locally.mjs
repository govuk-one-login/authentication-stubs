import * as jose from "jose";
import { CompactEncrypt, CompactSign, importSPKI } from "jose";


// This is the public key equivalent of the local private key in parameters.
// Both have been committed deliberately to allow for local running and testing.
const ipvPublicKeyPem = `-----BEGIN PUBLIC KEY-----
      MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApflLYqZm5IawLAHYtWoU
  vKdO7cFBmDIOASlGgGCEG0PVBC4FJH2pM3FUw72n7YTS+H73Y8ZfTNIgu9K7zxEa
  mCwimUAKU8Lsjq6Pqa0pZr2rE4l2MfO2j91uCcdlTzdM0kOkwcbzwqEdbDU+FJ4x
  FT5aaOWyuN/BKFsc5kNz2t4+OaeRu/ev3h7WCqh2MMW5PWDbR2lBnKZR8HvuXZc5
  ay0dUx098UjkLEBHIyT3FfzhXFMF2ZdOSysDMa64KwqeAWs6tjwM9+Bp3DYLkTsx
  BML/eqgIwdZI5QBCTxD8YC2oxC1obMspiAoEz05wt8cYscmT4rZAdBGMspuxNqo4
  6wIDAQAB
  -----END PUBLIC KEY-----`;

// This is the private key equivalent of the local public key in parameters.
// Both have been committed deliberately to allow for local running and testing.
const authPrivateSigningKeyEVCS = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgksszURcCxE4v8xSA
O9uwvvKDnntEb+2OBxQnsPs7vfKhRANCAAQnVd6isHfIQ7MlVbiy0wjl0gERdnca
j0qCr6EzRoVnxYW0/4WJVr0Pz5kd2wJkSVPsX/vKDEanPgh7XmH+rehn
-----END PRIVATE KEY-----
`;

// This is the private key equivalent of the local public key in parameters.
// Both have been committed deliberately to allow for local running and testing.
const authPrivateSigningKeyIPV = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSaOnCpAfj31OwM9+
IPuc+xPQZ6iCJHP+c3n4gOof+kihRANCAASZgtxRT+cjvTXQvGCl6Kst6k5m95C8
E66Lggy4GZsCn3tNfuUpbdbSeBRdiNs2J1wif/VGcj+6o/RoTa+IzP3C
-----END PRIVATE KEY-----
`;

const textEncoder = new TextEncoder();

const createSignedJwt = async (header, payload, signingKey) => {
  const privateKey = await jose.importPKCS8(signingKey, "ES256");
  return await new CompactSign(await textEncoder.encode(JSON.stringify(payload))).setProtectedHeader(header).sign(privateKey)
};

const createUserInfoClaims = async () => {
  const storageAccessTokenAlgorithm = { alg: "ES256" };
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
          await createSignedJwt(
            storageAccessTokenAlgorithm,
            storageAccessTokenPayload,
            authPrivateSigningKeyEVCS
          )
        ],
      },
    },
  };
};

const createRequestJwt = async () => {
  const payload = {
    sub: `urn:fdc:gov.uk:2022:fake_common_subject_identifier_${Math.floor(Math.random() * 100000)}`,
    scope: "reverification",
    claims: await createUserInfoClaims(),
    state: "test-state",
  };
  const publicKey = await importSPKI(ipvPublicKeyPem, "RSA-OAEP-256");
  const nestedJWS = await createSignedJwt({ alg: "ES256" }, payload, authPrivateSigningKeyIPV)

  return new CompactEncrypt(textEncoder.encode(nestedJWS))
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(publicKey);
};

(async () => {
  const encryptedRequest = await createRequestJwt();
  await console.log(`Encrypted request:\n------\n${encryptedRequest}`);
})();
