import { decodeJwt } from "jose";
import { logger } from "../logger.ts";
import { CodedError } from "../src/helpers/result-helper.ts";

const DELETE_ACCOUNT_TIMEOUT_MS = 25000;

export const deleteAccount = async (
  publicSubjectId: string | undefined,
  accountDataApiAccessToken: string | undefined
): Promise<void> => {
  const accountManagementApiUrl = process.env.ACCOUNT_MANAGEMENT_API_URL;
  if (!accountManagementApiUrl) {
    throw new CodedError(500, "ACCOUNT_MANAGEMENT_API_URL not set");
  }
  if (!publicSubjectId) {
    throw new CodedError(500, "public_sub not found");
  }
  if (!accountDataApiAccessToken) {
    throw new CodedError(500, "account_data_api_access_token not found");
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-ADAPI-AccessToken": accountDataApiAccessToken,
  };
  const { sid } = decodeJwt(accountDataApiAccessToken);
  if (typeof sid === "string") {
    headers["Session-Id"] = sid;
  }

  const url = `${accountManagementApiUrl}/v1/accounts/${encodeURIComponent(publicSubjectId)}`;
  logger.info("Deleting account through the Account Management API");

  let response: Response;
  try {
    response = await fetch(url, {
      method: "DELETE",
      headers,
      body: JSON.stringify({ clientId: "amc", reason: "USER_INITIATED" }),
      signal: AbortSignal.timeout(DELETE_ACCOUNT_TIMEOUT_MS),
    });
  } catch (error) {
    throw new CodedError(500, `Account deletion request failed: ${error}`);
  }

  if (response.status !== 204) {
    const body = await response.text();
    logger.error({ status: response.status, body }, "Account deletion failed");
    throw new CodedError(
      500,
      `Account deletion failed with status ${response.status}`
    );
  }

  logger.info("Account deleted");
};
