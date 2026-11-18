export enum HttpMethod {
  GET = "GET",
  POST = "POST",
  PUT = "PUT",
  DELETE = "DELETE",
}

export enum AMCStubEndpoints {
  AUTHORIZE = "/authorize",
  TOKEN = "/token",
  JOURNEY_OUTCOME = "/journeyoutcome",
}

export enum JoseAlgorithms {
  ES256 = "ES256",
  RSA_OAEP_256 = "RSA-OAEP-256",
  A256GCM = "A256GCM",
}

export enum AMCScopes {
  ACCOUNT_DELETE = "account-delete",
  PASSKEY_CREATE = "passkey-create",
}

export enum AccountDataAccessTokenScopes {
  PASSKEY_CREATE = "passkey-create",
  PASSKEY_RETRIEVE = "passkey-retrieve",
  PASSKEY_UPDATE = "passkey-update",
  PASSKEY_DELETE = "passkey-delete",
  ACCOUNT_DELETE = "account-delete",
  VERIFY_PASSWORD = "verify-password",
}

export const ACCOUNT_DELETE_ACCOUNT_DATA_SCOPES: string[] = [
  AccountDataAccessTokenScopes.ACCOUNT_DELETE,
  AccountDataAccessTokenScopes.VERIFY_PASSWORD,
];
