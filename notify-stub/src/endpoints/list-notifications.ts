import { APIGatewayProxyEvent, APIGatewayProxyResult } from "aws-lambda";
import { logger } from "../helpers/logger.js";
import {
  getNotifications,
  NotificationRecord,
} from "../services/notifications.js";
import { renderPage } from "../helpers/template.js";

const formatDate = (date: Date) =>
  date.toLocaleString("en-GB", {
    day: "2-digit",
    month: "2-digit",
    year: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

const relativeTime = (iso: string) => {
  const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  const diff = Math.floor((new Date(iso).getTime() - Date.now()) / 1000);
  if (Math.abs(diff) < 60) return rtf.format(diff, "seconds");
  if (Math.abs(diff) < 3600)
    return rtf.format(Math.floor(diff / 60), "minutes");
  return rtf.format(Math.floor(diff / 3600), "hours");
};

const maskPhone = (phone: string) =>
  phone.length <= 6
    ? phone
    : phone.slice(0, 4) + "*".repeat(phone.length - 6) + phone.slice(-2);

const maskEmail = (email: string) => {
  const [local, domain] = email.split("@");
  if (!domain) return email;
  const [mainLocal, plusPart] = local.split("+");
  const maskedLocal =
    mainLocal.slice(0, 2) + "***" + (plusPart ? "+" + plusPart : "");
  return maskedLocal + "@" + domain.slice(0, 2) + "***";
};

const maskDestination = (dest: string) =>
  dest.includes("@") ? maskEmail(dest) : maskPhone(dest);

const renderRow = (key: string, value: string, small = false) =>
  `<div class="govuk-summary-list__row">
    <dt class="govuk-summary-list__key">${key}</dt>
    <dd class="govuk-summary-list__value${small ? " govuk-body-s" : ""}">${value}</dd>
  </div>`;

const renderCard = (n: NotificationRecord) => {
  const masked = maskDestination(n.destination);
  const title = `${n.type.toUpperCase()} to ${masked} (${relativeTime(n.created_at)})`;

  return `<div class="govuk-summary-card">
  <div class="govuk-summary-card__title-wrapper">
    <h2 class="govuk-summary-card__title">${title}</h2>
  </div>
  <div class="govuk-summary-card__content">
    <dl class="govuk-summary-list govuk-summary-list--no-border">
      ${renderRow("Personalisation", `<pre>${JSON.stringify(n.personalisation || {}, null, 2)}</pre>`, true)}
      ${renderRow("Created At", formatDate(new Date(n.created_at)))}
      ${renderRow("TTL", formatDate(new Date(n.ttl * 1000)))}
      ${renderRow("Template ID", n.template_id)}
      ${renderRow("Notification ID", n.notification_id)}
      ${renderRow("Reference", n.reference || "")}
      ${renderRow("Type", n.type)}
    </dl>
  </div>
</div>`;
};

export const handler = async (
  _event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> => {
  logger.info("List notifications endpoint invoked");

  try {
    const notifications = await getNotifications();
    const cards = notifications.length
      ? notifications.map(renderCard).join("")
      : '<p class="govuk-body">No notifications found.</p>';
    const content = `<h1 class="govuk-heading-l">Notifications</h1>${cards}`;

    return {
      statusCode: 200,
      headers: { "Content-Type": "text/html" },
      body: renderPage(content),
    };
  } catch (error) {
    logger.error({ error }, "Error listing notifications");
    return {
      statusCode: 500,
      headers: { "Content-Type": "text/plain" },
      body: "Internal server error",
    };
  }
};
