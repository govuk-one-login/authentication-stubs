import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { logger } from "../helpers/logger";
import { successfulJsonResult, errorResult } from "../helpers/results";
import { createNotification } from "../services/notifications";
import { getNotifyBaseUrl, getFromEmail } from "../configuration";

interface EmailNotificationRequest {
  email_address: string;
  template_id: string;
  personalisation?: Record<string, unknown>;
  reference?: string;
  one_click_unsubscribe_url?: string;
  email_reply_to_id?: string;
}

interface EmailNotificationResponse {
  id: string;
  reference?: string;
  uri: string;
  template: {
    id: string;
    version: number;
    uri: string;
  };
  content: {
    subject: string;
    body: string;
    from_email: string;
    one_click_unsubscribe_url?: string;
  };
  scheduled_for: string | null;
}

export const handler = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  logger.info("Send Email endpoint invoked");

  try {
    if (event.httpMethod === "POST") {
      return await post(event);
    }
    return errorResult(405, `Method not allowed: ${event.httpMethod}`);
  } catch (error) {
    logger.error({ error }, "Unexpected error");
    return errorResult(500, "Internal server error");
  }
};

async function post(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  if (!event.body) {
    return errorResult(400, "Request body is required");
  }

  const request: EmailNotificationRequest = JSON.parse(event.body);

  if (!request.email_address) {
    return errorResult(400, "email_address is required");
  }
  if (!request.template_id) {
    return errorResult(400, "template_id is required");
  }

  const record = await createNotification(
    request.email_address,
    "email",
    request.template_id,
    request.reference,
    request.personalisation,
  );

  const baseUrl = getNotifyBaseUrl();

  const response: EmailNotificationResponse = {
    id: record.NotificationID,
    reference: request.reference,
    uri: `${baseUrl}/v2/notifications/${record.NotificationID}`,
    template: {
      id: request.template_id,
      version: 1,
      uri: `${baseUrl}/v2/template/${request.template_id}`,
    },
    content: {
      subject: `Email using template_id ${request.template_id}`,
      body: `Email using template_id ${request.template_id} with personalisation ${JSON.stringify(request.personalisation || {})}`,
      from_email: getFromEmail(),
      one_click_unsubscribe_url: request.one_click_unsubscribe_url,
    },
    scheduled_for: null,
  };

  return successfulJsonResult(201, response);
}
