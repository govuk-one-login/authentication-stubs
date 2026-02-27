import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import { randomUUID } from "node:crypto";
import {
  getTableName,
  getAwsRegion,
  getDynamoDbEndpoint,
  getNotificationTtlSeconds,
} from "../configuration";

const client = new DynamoDBClient({
  region: getAwsRegion(),
  ...(getDynamoDbEndpoint() && {
    endpoint: getDynamoDbEndpoint(),
  }),
});

const docClient = DynamoDBDocumentClient.from(client);

export interface NotificationRecord {
  Destination: string;
  NotificationID: string;
  type: "email" | "sms";
  template_id: string;
  reference?: string;
  personalisation?: Record<string, unknown>;
  status: string;
  created_at: string;
  ttl: number;
}

export const createNotification = async (
  destination: string,
  type: "email" | "sms",
  template_id: string,
  reference?: string,
  personalisation?: Record<string, unknown>,
): Promise<NotificationRecord> => {
  const notificationId = randomUUID();
  const now = new Date().toISOString();
  const ttl = Math.floor(Date.now() / 1000) + getNotificationTtlSeconds();

  const record: NotificationRecord = {
    Destination: destination,
    NotificationID: notificationId,
    type,
    template_id,
    reference,
    personalisation,
    status: "created",
    created_at: now,
    ttl,
  };

  await docClient.send(
    new PutCommand({
      TableName: getTableName(),
      Item: record,
    }),
  );

  return record;
};
