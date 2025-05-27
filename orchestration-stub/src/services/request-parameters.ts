import querystring, { ParsedUrlQuery } from "querystring";
import { CredentialTrustLevel } from "../types/credential-trust";
import { ChannelEnum } from "../types/channel";

export type RequestParameters = {
  confidence: CredentialTrustLevel;
  reauthenticate?: string;
  authenticated: boolean;
  channel: ChannelEnum;
  cookieConsent: string;
  loginHint?: string;
};

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
    loginHint: parsedForm["login-hint"] as string | undefined,
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
