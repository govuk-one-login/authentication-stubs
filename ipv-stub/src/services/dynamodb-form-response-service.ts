import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { Reverification } from "../interfaces/reverification-interface";

const client =
  process.env.ENVIRONMENT === "local"
    ? new DynamoDBClient({
        endpoint: "http://host.docker.internal:4566",
        region: "localhost", // Set a dummy region for local development
      })
    : new DynamoDBClient({});

const dynamo = DynamoDBDocument.from(client);

const tableName = `${process.env.ENVIRONMENT}-AuthIpvStub-Reverification`;

export const putReverificationWithAuthCode = async (
  authCode: string,
  reverification: Reverification
) => {
  return await dynamo.put({
    TableName: tableName,
    Item: {
      ReverificationId: authCode,
      reverification,
      ttl: oneHourFromNow(),
    },
  });
};

function oneHourFromNow() {
  return Math.floor(Date.now() / 1000) + 3600;
}
