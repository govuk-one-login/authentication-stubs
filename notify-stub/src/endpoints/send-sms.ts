import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { logger } from "../helpers/logger";
import { successfulJsonResult, errorResult } from "../helpers/results";
import { createNotification } from "../services/notifications";
import { getNotifyBaseUrl, getFromNumber } from "../configuration";

interface SmsNotificationRequest {
  phone_number: string;
  template_id: string;
  personalisation?: Record<string, unknown>;
  reference?: string;
  sms_sender_id?: string;
}

interface SmsNotificationResponse {
  id: string;
  reference?: string;
  uri: string;
  template: {
    id: string;
    version: number;
    uri: string;
  };
  content: {
    body: string;
    from_number: string;
  };
  scheduled_for: string | null;
}

export const handler = async (
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  logger.info("Send SMS endpoint invoked");

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

  const request: SmsNotificationRequest = JSON.parse(event.body);

  if (!request.phone_number) {
    return errorResult(400, "phone_number is required");
  }
  if (!request.template_id) {
    return errorResult(400, "template_id is required");
  }

  const record = await createNotification(
    request.phone_number,
    "sms",
    request.template_id,
    request.reference,
    request.personalisation,
  );

  const baseUrl = getNotifyBaseUrl();

  const response: SmsNotificationResponse = {
    id: record.NotificationID,
    reference: request.reference,
    uri: `${baseUrl}/v2/notifications/${record.NotificationID}`,
    template: {
      id: request.template_id,
      version: 1,
      uri: `${baseUrl}/v2/template/${request.template_id}`,
    },
    content: {
      body: `SMS using template_id ${request.template_id} with personalisation ${JSON.stringify(request.personalisation || {})}`,
      from_number: getFromNumber(),
    },
    scheduled_for: null,
  };

  return successfulJsonResult(201, response);
}
