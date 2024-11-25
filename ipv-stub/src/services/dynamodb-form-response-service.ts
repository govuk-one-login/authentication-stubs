import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { Reverification } from "../interfaces/reverification-interface";
import { logger } from "../helper/logger";

const client =
  process.env.ENVIRONMENT === "local"
    ? new DynamoDBClient({
        endpoint: "http://host.docker.internal:4566",
        region: "localhost", // Set a dummy region for local development
      })
    : new DynamoDBClient({});

const dynamo = DynamoDBDocument.from(client);

const tableName = `${process.env.ENVIRONMENT}-AuthIpvStub-Reverification`;
const authCodePrefix = "authcode";
const accessTokenPrefix = "accesstoken";

export const putReverificationWithAuthCode = async (
  authCode: string,
  reverification: Reverification
) => {
  return await dynamo.put({
    TableName: tableName,
    Item: {
      ReverificationId: [authCodePrefix, authCode].join("-"),
      reverification,
      ttl: oneHourFromNow(),
    },
  });
};

export const getReverificationWithAuthCode = async (
    authCode: string
): Promise<string | undefined> => {
  logger.info(`Looking up ${authCode}`);
  const result = await dynamo.get({
    TableName: tableName,
    Key: {
      ReverificationId: [authCodePrefix, authCode].join("-"),
    },
  });

  return result.Item?.reverification;
};

export const putReverificationWithAccessToken = async (
    accessToken: string,
    reverification: Reverification
) => {
  return await dynamo.put({
    TableName: tableName,
    Item: {
      ReverificationId: [accessTokenPrefix, accessToken].join("-"),
      reverification,
      ttl: oneHourFromNow(),
    },
  });
};

export const getReverificationWithAccessToken = async (
  accessToken: string
): Promise<string | undefined> => {
  logger.info(`Looking up ${accessToken}`);
  const result = await dynamo.get({
    TableName: tableName,
    Key: {
      ReverificationId: [accessTokenPrefix, accessToken].join("-"),
    },
  });

  return result.Item?.reverification;
};

function oneHourFromNow() {
  return Math.floor(Date.now() / 1000) + 3600;
}
