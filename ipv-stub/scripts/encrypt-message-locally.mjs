import { CompactEncrypt, CompactSign, importSPKI } from "jose";
import * as crypto from "crypto"


//This is the public key equivalent of the local private key in parameters.
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

const authPrivateKeyPem = `-----BEGIN EC PARAMETERS-----
BggqhkjOPQMBBw==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBXg7vITxDg+j65DVa5lbmJU3ToUxqE2xvVBa7UImovtoAoGCCqGSM49
AwEHoUQDQgAET5PDE5I+OVbwCyTXrWO/DL+1LEiM+BAY0r+XXoRaKWMryDCCaYvU
M9xty4GWOIwqqNLxotddRqU2FiM2Z83qQw==
-----END EC PRIVATE KEY-----
`;

const createSignedJwt = async (header, payload) => {
  const privateKey = crypto.createPrivateKey({
    key: authPrivateKeyPem,
    format: 'pem',
    type: 'sec1', // Important for EC keys
  });
  return await new CompactSign(Uint8Array.from(payload)).setProtectedHeader(header).sign(privateKey);
};

const createUserInfoClaims = () => {
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
          // Tried with the following unsigned part of a jwt from jwt.io eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJlbmMiOiJBMjU2R0NNIn0.fSKnYE_XKKMFHzFHhTDi8qWWPoHu4Is3ARO1s_tomZnFX8CWlDKdWvXhqsOflpG8tak-0JUs5gVUkhYaB6TbSzUdgWVfDU9Y0IpZ0WnkGjhFESPMrEUmMNhX5ekVhoKBh1T0w0VYvCTP728ExThavwJpPopxmVER8qx5IXmecOK8gACsuFY9qIDYpmLK8ywipWYn1mbuGQMKVqWXdkINUMdkuNlYWe7HRKY_lMwxKOpq1wZg1-F5ujkuYE5St5cX9JCeW8F1-8ARxplo0A-mDlkjfjN6xvHq1saTXPXAS1dqNLP5AzDLOJ_G0fFrIOWBDVanHoxJ86LwI50s2typGw.edIYHKXesBQq0g_q.QiTfaYU89jsaQpkXUJbCAlziDUoblr1u0OCGe1qLoJsAckRMqrwaxRGom--ZEHl-hPUrv_p8RxkGKij65lhj4FcbLULsFvDz4-v2vhMMYXMDQ_o-5o48CdhZnr1TK4H0HJoh0lLKcv7KSqP8.4c2tGizi_p7ssJIdiizSwA
          // This works, maybe we shouldn't sign internal jwt
          createSignedJwt(
            storageAccessTokenAlgorithm,
            storageAccessTokenPayload
          ),
        ],
      },
    },
  };
};

const createRequestJwt = async () => {
  const header = { alg: 'ES256' };
  const payload = {
    scope: 'reverification',
    claims: createUserInfoClaims(),
    state: 'test-state',
  };
  return createSignedJwt(header, payload);
};

(async () => {
  const signedJwt = await createRequestJwt();
  const publicKey = await importSPKI(ipvPublicKeyPem, "RSA-OAEP-256");
  const encryptedRequest = await new CompactEncrypt(new TextEncoder().encode(signedJwt))
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(publicKey);

  console.log(`Encrypted request:\n------\n${encryptedRequest}`);
})();
