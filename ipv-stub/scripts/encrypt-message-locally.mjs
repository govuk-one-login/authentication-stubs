#!/usr/bin/env node

import * as jose from "jose";
import { CompactEncrypt, CompactSign, importSPKI } from "jose";
import keys from "../src/data/keys.json" assert { type: "json" };

// This is the public key equivalent of the local private key in parameters.
// Both have been committed deliberately to allow for local running and testing.
const ipvPublicEncryptionKeyPem = keys.ipv_public_encryption_key;

// This is the private key equivalent of the local public key in parameters.
// Both have been committed deliberately to allow for local running and testing.
const authPrivateSigningKeyEVCS = keys.authPrivateSigningKeyEVCS;

// This is the private key equivalent of the local public key in parameters.
// Both have been committed deliberately to allow for local running and testing.
const authPrivateSigningKeyIPV = keys.authPrivateSigningKeyIPV;

const textEncoder = new TextEncoder();

const createSignedJwt = async (header, payload, signingKey) => {
  const privateKey = await jose.importPKCS8(signingKey, "ES256");
  return await new CompactSign(
    await textEncoder.encode(JSON.stringify(payload))
  )
    .setProtectedHeader(header)
    .sign(privateKey);
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
          ),
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
  const publicKey = await importSPKI(ipvPublicEncryptionKeyPem, "RSA-OAEP-256");
  const nestedJWS = await createSignedJwt(
    { alg: "ES256" },
    payload,
    authPrivateSigningKeyIPV
  );

  return new CompactEncrypt(textEncoder.encode(nestedJWS))
    .setProtectedHeader({ alg: "RSA-OAEP-256", enc: "A256GCM" })
    .encrypt(publicKey);
};

(async () => {
  const encryptedRequest = await createRequestJwt();
  await console.log(`Encrypted request:\n------\n${encryptedRequest}`);
})();
