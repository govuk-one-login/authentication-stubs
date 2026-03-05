export const getTableName = (): string => {
  return process.env.NOTIFICATIONS_TABLE_NAME!;
};

export const getNotifyBaseUrl = (): string => {
  const protocol = process.env.NOTIFY_PROTOCOL!;
  const domain = process.env.NOTIFY_DOMAIN!;
  return `${protocol}://${domain}`;
};

export const getNotificationTtlSeconds = (): number => {
  return Number.parseInt(process.env.NOTIFICATION_TTL_SECONDS || "1800", 10);
};

export const getAwsRegion = (): string => {
  return process.env.AWS_REGION || "eu-west-2";
};

export const isLocalEnvironment = (): boolean => {
  return !!process.env.AWS_SAM_LOCAL;
};

export const getDynamoDbEndpoint = (): string | undefined => {
  return isLocalEnvironment() ? "http://host.docker.internal:4566" : undefined;
};

export const getFromNumber = (): string => {
  return process.env.FROM_NUMBER || "NotifyStub";
};
