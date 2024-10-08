import { APIGatewayProxyEventHeaders } from "aws-lambda";
import * as crypto from "node:crypto";

export const getCookie = (
  cookies: string | undefined,
  name: string,
): string | undefined => {
  if (cookies === undefined) {
    return undefined;
  }

  const cookie = cookies.split("; ").filter((it) => it.startsWith(`${name}=`));
  return cookie[0]?.split("=")[1];
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
