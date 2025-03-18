import querystring, { ParsedUrlQuery } from "querystring";
import { CredentialTrustLevel } from "../types/credential-trust";
import { ChannelEnum } from "../types/channel";

export type RequestParameters = {
  confidence: CredentialTrustLevel;
  reauthenticate?: string;
  authenticated: boolean;
  authenticatedLevel?: CredentialTrustLevel;
  channel: ChannelEnum;
  cookieConsent: string;
};

export const parseRequestParameters = (
  body: string | null,
): RequestParameters => {
  if (body === null) {
    throw new Error("No body");
  }

  const parsedForm = querystring.parse(body);

  const existingAuthentication = getExistingAuthentication(parsedForm);
  return {
    confidence: validateCredentialTrustLevel(parsedForm.level),
    reauthenticate: getReauthenticate(parsedForm),
    authenticated: existingAuthentication.authenticated,
    authenticatedLevel: existingAuthentication.authenticatedLevel,
    channel: getChannel(parsedForm.channel),
    cookieConsent: parsedForm["cookie-consent"],
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

const getExistingAuthentication = (form: ParsedUrlQuery) => {
  const authenticated = form.authenticated === "yes";
  const authenticatedLevel = authenticated
    ? validateCredentialTrustLevel(form.authenticatedLevel)
    : undefined;
  return { authenticated, authenticatedLevel };
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
      channel === ChannelEnum.STRATEGIC_APP)
  ) {
    return channel;
  }
  throw new Error("Unknown channel: " + channel);
};
