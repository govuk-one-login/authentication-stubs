import { CompactSign, importPKCS8 } from "jose";

type ProtectedHeader = {
  alg: string;
  kid?: string;
};

export async function createSignedJwt(
  header: string,
  payload: unknown,
  signingKey: string,
  kid?: string
) {
  const textEncoder = new TextEncoder();
  const privateKey = await importPKCS8(signingKey, header);
  const protectedHeader: ProtectedHeader = { alg: header };
  if (kid) {
    protectedHeader.kid = kid;
  }
  return new CompactSign(textEncoder.encode(JSON.stringify(payload)))
    .setProtectedHeader(protectedHeader)
    .sign(privateKey);
}
