import querystring, { ParsedUrlQuery } from "querystring";
import { CredentialTrustLevel } from "../types/credential-trust";
import { ChannelEnum } from "../types/channel";
import { SubjectTypeEnum } from "../types/subject-type";

export type RequestParameters = {
  confidence: CredentialTrustLevel;
  reauthenticate?: string;
  authenticated: boolean;
  channel: ChannelEnum;
  cookieConsent: string;
  scopes: string[];
  identityRequired: boolean;
  subjectType: SubjectTypeEnum;
};

export const SELECTABLE_SCOPES = [
  "email",
  "phone",
  "am",
  "govuk-account",
] as const;

const DEFAULT_SCOPES = ["openid", "email", "phone"];

export const parseRequestParameters = (
  body: string | null,
): RequestParameters => {
  if (body === null) {
    throw new Error("No body");
  }

  const parsedForm = querystring.parse(body);

  return {
    confidence: validateCredentialTrustLevel(parsedForm.level),
    reauthenticate: getReauthenticate(parsedForm),
    authenticated: parsedForm.authenticated === "yes",
    channel: getChannel(parsedForm.channel),
    cookieConsent: parsedForm["cookie-consent"] as string,
    scopes: getScopes(parsedForm),
    identityRequired: parsedForm["identity-required"] === "yes",
    subjectType: getSubjectType(parsedForm["subject-type"]),
  };
};

const validateCredentialTrustLevel = (
  level: string | string[] | undefined,
): CredentialTrustLevel => {
  if (level === "Cl" || level === "Cl.Cm") {
    return level;
  }
  throw new Error("Unknown level " + level);
};

const getReauthenticate = (form: ParsedUrlQuery): string | undefined => {
  if (typeof form.reauthenticate === "string" && form.reauthenticate !== "") {
    return form.reauthenticate;
  }
};

const getChannel = (channel: string | string[] | undefined): ChannelEnum => {
  if (
    typeof channel === "string" &&
    (channel === ChannelEnum.NONE ||
      channel === ChannelEnum.WEB ||
      channel === ChannelEnum.STRATEGIC_APP ||
      channel === ChannelEnum.GENERIC_APP)
  ) {
    return channel;
  }
  throw new Error("Unknown channel: " + channel);
};

const getScopes = (form: ParsedUrlQuery): string[] => {
  const raw = form.scope;
  if (raw === undefined) {
    return [...DEFAULT_SCOPES];
  }

  const selected = (Array.isArray(raw) ? raw : [raw])
    .filter((s): s is string => typeof s === "string" && s !== "")
    .filter((s) => (SELECTABLE_SCOPES as readonly string[]).includes(s));

  const scopes = new Set<string>(["openid", ...selected]);
  return [...scopes];
};

const getSubjectType = (
  subjectType: string | string[] | undefined,
): SubjectTypeEnum => {
  if (
    subjectType === SubjectTypeEnum.PAIRWISE ||
    subjectType === SubjectTypeEnum.PUBLIC
  ) {
    return subjectType;
  }
  // Default preserves the stub's original behaviour.
  return SubjectTypeEnum.PAIRWISE;
};
