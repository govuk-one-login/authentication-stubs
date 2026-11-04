import { SubjectTypeEnum } from "../types/subject-type";

export const AuthUserInfoClaim = {
  LEGACY_SUBJECT_ID: "legacy_subject_id",
  PUBLIC_SUBJECT_ID: "public_subject_id",
  LOCAL_ACCOUNT_ID: "local_account_id",
  RP_PAIRWISE_ID: "rp_pairwise_id",
  EMAIL: "email",
  EMAIL_VERIFIED: "email_verified",
  PHONE_NUMBER: "phone_number",
  PHONE_VERIFIED: "phone_number_verified",
  SALT: "salt",
  VERIFIED_MFA_METHOD_TYPE: "verified_mfa_method_type",
  NEW_ACCOUNT: "new_account",
  UPLIFT_REQUIRED: "uplift_required",
  ACHIEVED_CREDENTIAL_STRENGTH: "achieved_credential_strength",
  ACCOUNT_DATA_API_ACCESS_TOKEN: "account_data_api_access_token",
} as const;

export type AuthUserInfoClaimValue =
  (typeof AuthUserInfoClaim)[keyof typeof AuthUserInfoClaim];

export type ClaimsRequestInputs = {
  scopes: string[];
  identityRequired: boolean;
  subjectType: SubjectTypeEnum;
};

const AM_SCOPE = "am";
const GOVUK_ACCOUNT_SCOPE = "govuk-account";
const PHONE_SCOPE = "phone";
const EMAIL_SCOPE = "email";

export const buildUserInfoClaims = ({
  scopes,
  identityRequired,
  subjectType,
}: ClaimsRequestInputs): AuthUserInfoClaimValue[] => {
  const claims = new Set<AuthUserInfoClaimValue>();

  // Always requested.
  claims.add(AuthUserInfoClaim.EMAIL);
  claims.add(AuthUserInfoClaim.LOCAL_ACCOUNT_ID);
  claims.add(AuthUserInfoClaim.VERIFIED_MFA_METHOD_TYPE);
  claims.add(AuthUserInfoClaim.UPLIFT_REQUIRED);
  claims.add(AuthUserInfoClaim.ACHIEVED_CREDENTIAL_STRENGTH);

  if (identityRequired) {
    claims.add(AuthUserInfoClaim.SALT);
    claims.add(AuthUserInfoClaim.EMAIL_VERIFIED);
    claims.add(AuthUserInfoClaim.PHONE_NUMBER);
  }

  const amScopePresent = scopes.includes(AM_SCOPE);
  if (amScopePresent) {
    claims.add(AuthUserInfoClaim.PUBLIC_SUBJECT_ID);
    claims.add(AuthUserInfoClaim.ACCOUNT_DATA_API_ACCESS_TOKEN);
  } else if (subjectType === SubjectTypeEnum.PUBLIC) {
    claims.add(AuthUserInfoClaim.PUBLIC_SUBJECT_ID);
  }

  if (scopes.includes(GOVUK_ACCOUNT_SCOPE)) {
    claims.add(AuthUserInfoClaim.LEGACY_SUBJECT_ID);
  }
  if (scopes.includes(PHONE_SCOPE)) {
    claims.add(AuthUserInfoClaim.PHONE_NUMBER);
    claims.add(AuthUserInfoClaim.PHONE_VERIFIED);
  }
  if (scopes.includes(EMAIL_SCOPE)) {
    claims.add(AuthUserInfoClaim.EMAIL_VERIFIED);
  }

  return [...claims].sort((a, b) => a.localeCompare(b));
};

export const buildClaimPayload = (
  inputs: ClaimsRequestInputs,
): { userinfo: Record<string, null> } | undefined => {
  const claims = buildUserInfoClaims(inputs);
  if (claims.length === 0) {
    return undefined;
  }
  const userinfo: Record<string, null> = {};
  for (const claim of claims) {
    userinfo[claim] = null;
  }
  return { userinfo };
};
