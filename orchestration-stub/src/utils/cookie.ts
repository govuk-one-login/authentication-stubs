import { APIGatewayProxyEventHeaders } from "aws-lambda";
import * as crypto from "node:crypto";

export const getCookie = (
  cookies: string | undefined,
  name: string,
): string | undefined => {
  if (cookies === undefined) {
    return undefined;
  }

  const matchingCookies = cookies.split("; ").filter((it) => it.startsWith(`${name}=`));
  
  if (matchingCookies.length <= 1) {
    return matchingCookies[0]?.split("=")[1];
  }

  // When multiple cookies exist, prefer the one for the current domain
  const cookieDomain = process.env.COOKIE_DOMAIN;
  if (cookieDomain?.includes("authdev")) {
    // Return the last cookie (most specific domain)
    return matchingCookies[matchingCookies.length - 1]?.split("=")[1];
  }
  
  return matchingCookies[0]?.split("=")[1];
};

export const getOrCreatePersistentSessionId = (
  headers: APIGatewayProxyEventHeaders,
): string => {
  const cookieHeader = headers["cookie"];
  const existingPersistentCookie = getCookie(
    cookieHeader,
    "di-persistent-session-id",
  );
  return existingPersistentCookie ?? createPersistentSessionId();
};

const createPersistentSessionId = () => {
  const id = crypto.randomBytes(20).toString("base64url");
  const timestamp = Date.now();
  return `${id}--${timestamp}`;
};
