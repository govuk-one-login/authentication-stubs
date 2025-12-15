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

export enum joseAlgorithms {
  ES256 = "ES256",
  RSA_OAEP_256 = "RSA-OAEP-256",
  A256GCM = "A256GCM",
}

export enum amcScopes {
  ACCOUNT_DELETE = "account-delete",
}
