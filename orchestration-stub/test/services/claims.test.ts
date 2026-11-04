import {
  AuthUserInfoClaim,
  buildClaimPayload,
  buildUserInfoClaims,
} from "../../src/services/claims";
import { SubjectTypeEnum } from "../../src/types/subject-type";

const ALWAYS = [
  AuthUserInfoClaim.EMAIL,
  AuthUserInfoClaim.LOCAL_ACCOUNT_ID,
  AuthUserInfoClaim.VERIFIED_MFA_METHOD_TYPE,
  AuthUserInfoClaim.UPLIFT_REQUIRED,
  AuthUserInfoClaim.ACHIEVED_CREDENTIAL_STRENGTH,
];

describe("buildUserInfoClaims", () => {
  it("always requests the base claims", () => {
    const claims = buildUserInfoClaims({
      scopes: ["openid"],
      identityRequired: false,
      subjectType: SubjectTypeEnum.PAIRWISE,
    });
    ALWAYS.forEach((c) => expect(claims).toContain(c));
  });

  it("adds email_verified when email scope present", () => {
    const claims = buildUserInfoClaims({
      scopes: ["openid", "email"],
      identityRequired: false,
      subjectType: SubjectTypeEnum.PAIRWISE,
    });
    expect(claims).toContain(AuthUserInfoClaim.EMAIL_VERIFIED);
  });

  it("adds phone_number and phone_number_verified when phone scope present", () => {
    const claims = buildUserInfoClaims({
      scopes: ["openid", "phone"],
      identityRequired: false,
      subjectType: SubjectTypeEnum.PAIRWISE,
    });
    expect(claims).toContain(AuthUserInfoClaim.PHONE_NUMBER);
    expect(claims).toContain(AuthUserInfoClaim.PHONE_VERIFIED);
  });

  it("adds salt, email_verified and phone_number when identity required", () => {
    const claims = buildUserInfoClaims({
      scopes: ["openid"],
      identityRequired: true,
      subjectType: SubjectTypeEnum.PAIRWISE,
    });
    expect(claims).toContain(AuthUserInfoClaim.SALT);
    expect(claims).toContain(AuthUserInfoClaim.EMAIL_VERIFIED);
    expect(claims).toContain(AuthUserInfoClaim.PHONE_NUMBER);
  });

  it("adds public_subject_id and account data token for am scope", () => {
    const claims = buildUserInfoClaims({
      scopes: ["openid", "am"],
      identityRequired: false,
      subjectType: SubjectTypeEnum.PAIRWISE,
    });
    expect(claims).toContain(AuthUserInfoClaim.PUBLIC_SUBJECT_ID);
    expect(claims).toContain(AuthUserInfoClaim.ACCOUNT_DATA_API_ACCESS_TOKEN);
  });

  it("adds public_subject_id for a PUBLIC subject type without am scope", () => {
    const claims = buildUserInfoClaims({
      scopes: ["openid"],
      identityRequired: false,
      subjectType: SubjectTypeEnum.PUBLIC,
    });
    expect(claims).toContain(AuthUserInfoClaim.PUBLIC_SUBJECT_ID);
    expect(claims).not.toContain(
      AuthUserInfoClaim.ACCOUNT_DATA_API_ACCESS_TOKEN,
    );
  });

  it("adds legacy_subject_id for govuk-account scope", () => {
    const claims = buildUserInfoClaims({
      scopes: ["openid", "govuk-account"],
      identityRequired: false,
      subjectType: SubjectTypeEnum.PAIRWISE,
    });
    expect(claims).toContain(AuthUserInfoClaim.LEGACY_SUBJECT_ID);
  });

  it("does not produce the legacy incorrect claim names", () => {
    const claims = buildUserInfoClaims({
      scopes: ["openid", "email", "phone", "am", "govuk-account"],
      identityRequired: true,
      subjectType: SubjectTypeEnum.PUBLIC,
    });
    expect(claims).not.toContain("public_account_id");
    expect(claims).not.toContain("legacy_account_id");
  });

  it("returns a sorted, de-duplicated list", () => {
    const claims = buildUserInfoClaims({
      scopes: ["openid", "email", "phone"],
      identityRequired: true,
      subjectType: SubjectTypeEnum.PAIRWISE,
    });
    const sorted = [...claims].sort((a, b) => a.localeCompare(b));
    expect(claims).toEqual(sorted);
    expect(new Set(claims).size).toBe(claims.length);
  });
});

describe("buildClaimPayload", () => {
  it("wraps claims under a userinfo object with null values", () => {
    const payload = buildClaimPayload({
      scopes: ["openid", "email"],
      identityRequired: false,
      subjectType: SubjectTypeEnum.PAIRWISE,
    });
    expect(payload).toBeDefined();
    expect(payload?.userinfo[AuthUserInfoClaim.EMAIL]).toBeNull();
    expect(payload?.userinfo[AuthUserInfoClaim.EMAIL_VERIFIED]).toBeNull();
  });
});
