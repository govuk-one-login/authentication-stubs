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

export enum SFADAccessTokenScopes {
  ACCOUNT_DELETE = "account-delete",
}

export enum AccessTokenApi {
  ACCOUNT_MANAGEMENT = "account-management",
  ACCOUNT_DATA = "account-data",
}

export enum AccessTokenFieldName {
  ACCOUNT_MANAGEMENT = "account_management_api_access_token",
  ACCOUNT_DATA = "account_data_api_access_token",
}
