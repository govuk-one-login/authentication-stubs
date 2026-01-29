import keys from "../data/keys.json" with { type: "json" };
import {
  CompactEncrypt,
  CompactJWSHeaderParameters,
  CompactSign,
  importPKCS8,
  importSPKI,
  JWTPayload,
} from "jose";
import { AMCScopes, JoseAlgorithms } from "../src/types/enums.ts";

// This is the public key equivalent of the local private key in parameters.
// Both have been committed deliberately to allow for local running and testing.
const amcPublicEncryptionKey = keys.amcPublicEncryptionKey;

// This is the private key equivalent of the local public key in parameters.
// Both have been committed deliberately to allow for local running and testing.
const authPrivateSigningKeyAMCAudience = keys.authPrivateSigningKeyAMCAudience;

// This is the private key equivalent of the local public key in parameters.
// Both have been committed deliberately to allow for local running and testing.
const authPrivateSigningKeyAuthAudience =
  keys.authPrivateSigningKeyAuthAudience;

const textEncoder = new TextEncoder();

const createSignedJwt = async (
  header: CompactJWSHeaderParameters,
  payload: JWTPayload,
  signingKey: string
) => {
  const privateKey = await importPKCS8(signingKey, JoseAlgorithms.ES256);
  return await new CompactSign(textEncoder.encode(JSON.stringify(payload)))
    .setProtectedHeader(header)
    .sign(privateKey);
};

const createAccessToken = async (sub: string) => {
  const protectedHeader = {
    alg: JoseAlgorithms.ES256,
    typ: "at+jwt",
  };
  const now = Math.floor(Date.now() / 1000);
  const accessTokenPayload = {
    sub: sub,
    scope: [AMCScopes.ACCOUNT_DELETE],
    iss: "https://signin.account.gov.uk",
    aud: "https://manage.account.gov.uk",
    exp: now + 3600,
    iat: now,
    client_id: "authentication",
    jti: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    sid: "sess_abc123def456ghi789jkl012mno345pqr",
  };

  return createSignedJwt(
    protectedHeader,
    accessTokenPayload,
    authPrivateSigningKeyAuthAudience
  );
};

const createRequestJWT = async () => {
  const publicKey = await importSPKI(
    amcPublicEncryptionKey,
    JoseAlgorithms.RSA_OAEP_256
  );
  const sub = "urn:fdc:gov.uk:2022:fake_common_subject_identifier";
  const now = Math.floor(Date.now() / 1000);
  const requestPayload = {
    iss: "https://signin.account.gov.uk",
    client_id: "auth_amc",
    aud: "https://api.manage.account.gov.uk",
    response_type: "code",
    redirect_uri: "https://signin.account.gov.uk/{callback_endpoint}",
    scope: [AMCScopes.ACCOUNT_DELETE],
    state: "S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw",
    jti: "dfccf751-be55-4df4-aa3f-a993193d5216",
    iat: now,
    exp: now + 3600,
    nbf: now,
    access_token: await createAccessToken(sub),
    sub: sub,
    public_sub: "550e8400-e29b-41d4-a716-446655440000",
    email: "test@digital.cabinet-office.gov.uk",
    govuk_signin_journey_id:
      "lBG99Z78pnrPUbdKDIaHobHV9DE.taUSm4TwLOGNIkmBTF9rzdIDj5s",
  };

  const signedPayload = await new CompactSign(
    textEncoder.encode(JSON.stringify(requestPayload))
  )
    .setProtectedHeader({ alg: JoseAlgorithms.ES256, typ: "JWT" })
    .sign(
      await importPKCS8(authPrivateSigningKeyAMCAudience, JoseAlgorithms.ES256)
    );

  return new CompactEncrypt(textEncoder.encode(signedPayload))
    .setProtectedHeader({
      alg: JoseAlgorithms.RSA_OAEP_256,
      enc: JoseAlgorithms.A256GCM,
    })
    .encrypt(publicKey);
};

const encryptedRequest = await createRequestJWT();
const localUrl = `http://localhost:3000/authorize?request=${encryptedRequest}`;

console.log(`Encrypted request:\n${encryptedRequest}\n`);
console.log(`Local Authorization URL:\n${localUrl}\n`);
