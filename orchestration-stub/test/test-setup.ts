import * as jose from "jose";

export type TestKeys = {
  // EC P-256 private key (PKCS8 PEM) used for ES256 signing by the stub.
  privateKeyPem: string;
  // EC P-256 public key used in tests to verify signatures produced by the stub.
  publicSigningKey: jose.CryptoKey;
  // RSA private key used in tests to decrypt JWEs produced by the stub.
  rsaPrivateKey: jose.CryptoKey;
};

/**
 * Generates fresh key material and wires up the environment variables that the
 * index and callback handlers read. Must be called (and awaited) before the
 * handler modules are imported, because some module-level constants capture
 * environment values at import time.
 */
export const setupHandlerEnv = async (): Promise<TestKeys> => {
  const signingKeyPair = await jose.generateKeyPair("ES256", {
    extractable: true,
  });
  const encryptionKeyPair = await jose.generateKeyPair("RSA-OAEP-256", {
    extractable: true,
  });

  const privateKeyPem = await jose.exportPKCS8(signingKeyPair.privateKey);
  const authPubKeyPem = await jose.exportSPKI(encryptionKeyPair.publicKey);

  process.env.PRIVATE_KEY = privateKeyPem;
  process.env.AUTH_PUB_KEY = authPubKeyPem;
  process.env.AUTHENTICATION_BACKEND_URL = "https://backend.example.com/";
  process.env.AUTHENTICATION_FRONTEND_URL = "https://frontend.example.com/";
  process.env.STUB_URL = "https://stub.example.com/";
  process.env.RP_CLIENT_ID = "test-rp-client-id";
  process.env.RP_SECTOR_HOST = "test-rp-sector-host";
  process.env.COOKIE_DOMAIN = "none";

  return {
    privateKeyPem,
    publicSigningKey: signingKeyPair.publicKey,
    rsaPrivateKey: encryptionKeyPair.privateKey,
  };
};

export const buildEvent = (
  overrides: Partial<{
    httpMethod: string;
    headers: Record<string, string | undefined>;
    body: string | null;
    queryStringParameters: Record<string, string> | null;
  }> = {},
) =>
  ({
    httpMethod: "GET",
    headers: {},
    body: null,
    queryStringParameters: null,
    ...overrides,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  }) as any;
