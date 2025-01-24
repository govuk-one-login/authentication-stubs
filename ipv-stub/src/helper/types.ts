export type DecodedRequest = {
  sub: string;
  scope: string;
  state: string;
  claims: DecodedUserInfoClaim;
  redirect_uri: string;
};

export type DecodedUserInfoClaim = {
  userinfo: {
    "https://vocab.account.gov.uk/v1/storageAccessToken": {
      values: [DecodedStorageAccessToken];
    };
  };
};

export type EncodedUserInfoClaim = {
  "https://vocab.account.gov.uk/v1/storageAccessToken": { values: [string] };
};

export type DecodedStorageAccessToken = {
  iss: string;
  aud: string;
  exp: number;
  iat: number;
  sub: string;
  scope: string;
  jti: string;
};
