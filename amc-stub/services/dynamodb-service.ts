import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocument } from "@aws-sdk/lib-dynamodb";
import { AMCAuthorizationResult } from "../src/types/types.ts";

const client =
  process.env.ENVIRONMENT === "local"
    ? new DynamoDBClient({
        endpoint: "http://host.docker.internal:4567",
        region: "eu-west-2",
      })
    : new DynamoDBClient({});

const dynamo = DynamoDBDocument.from(client);

const tableName = `${process.env.ENVIRONMENT}-AMCStub-Authorization`;
const authCodePrefix = "authcode";

export const putAMCAuthorizationResultWithAuthCode = async (
  authCode: string,
  amcAuthorizationResult: AMCAuthorizationResult
) => {
  return await dynamo.put({
    TableName: tableName,
    Item: {
      AuthorizationId: [authCodePrefix, authCode].join("-"),
      authorization: amcAuthorizationResult,
      ttl: oneHourFromNow(),
    },
  });
};

function oneHourFromNow() {
  return Math.floor(Date.now() / 1000) + 3600;
}
