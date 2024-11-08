const { CompactEncrypt, importSPKI } = require("jose");

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

const algorithm = { alg: "some-alg" };
const payload = { foo: "bar" };
const signature = { sig: "a-signature" };

const stringToEncrypt = [algorithm, payload, signature]
  .map((e) => JSON.stringify(e))
  .map((element) => Buffer.from(element.toString(), "utf-8").toString("base64"))
  .join(".");

const dataToEncrypt = Uint8Array.from(stringToEncrypt, (c) => c.charCodeAt(0));
(async () => {
  const publicKey = await importSPKI(publicKeyPem, "RSA-OAEP-256");

  const jwe = await new CompactEncrypt(dataToEncrypt)
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(publicKey);

  console.log("Encrypted (JWE Compact):", jwe);
})();
