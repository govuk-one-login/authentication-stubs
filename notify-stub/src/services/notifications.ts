import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand } from "@aws-sdk/lib-dynamodb";
import { randomUUID } from "node:crypto";
import {
  getTableName,
  getAwsRegion,
  getDynamoDbEndpoint,
  getNotificationTtlSeconds,
} from "../configuration.js";

const client = new DynamoDBClient({
  region: getAwsRegion(),
  ...(getDynamoDbEndpoint() && {
    endpoint: getDynamoDbEndpoint(),
    credentials: {
      accessKeyId: "test",
      secretAccessKey: "test",
    },
  }),
});

const docClient = DynamoDBDocumentClient.from(client);

export interface NotificationRecord {
  destination: string;
  notification_id: string;
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
  const notification_id = randomUUID();
  const now = new Date().toISOString();
  const ttl = Math.floor(Date.now() / 1000) + getNotificationTtlSeconds();

  const record: NotificationRecord = {
    destination,
    notification_id,
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
