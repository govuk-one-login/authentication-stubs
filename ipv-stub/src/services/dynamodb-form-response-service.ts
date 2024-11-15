import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";

const client =
  process.env.ENVIRONMENT === "local"
    ? new DynamoDBClient({
        endpoint: "http://host.docker.internal:8000",
        region: "localhost", // Set a dummy region for local development
      })
    : new DynamoDBClient({});

const dynamo = DynamoDBDocument.from(client);

const tableName = `${process.env.ENVIRONMENT}-AuthIpvStub-UserIdentity`;

export const putStateWithAuthCode = async (authCode: string, state: string) => {
  return await dynamo.put({
    TableName: tableName,
    Item: {
      UserIdentityId: authCode + "-state",
      state,
      ttl: getOneDayTimestamp(),
    },
  });
};

export const getStateWithAuthCode = async (
  authCode: string
): Promise<string> => {
  const response = await dynamo.get({
    TableName: tableName,
    Key: { UserIdentityId: authCode + "-state" },
  });

  return response.Item?.state;
};

function getOneDayTimestamp() {
  const date = new Date();
  date.setDate(date.getDate() + 1);
  return Math.floor(date.getTime() / 1000);
}
