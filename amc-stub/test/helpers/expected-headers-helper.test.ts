import { expect } from "chai";
import { validateRequiredHeaders } from "../../src/helpers/expected-headers-helper.ts";
import { createTestEvent } from "../test-helpers.ts";
import { HttpMethod } from "../../src/types/enums.ts";

describe("validateRequiredHeaders", () => {
  it("should return null when all required headers are present", () => {
    const event = createTestEvent(HttpMethod.GET, "/test", null, null, {
      "di-persistent-session-id": "persistent-session-123",
      "session-id": "session-456",
      "client-session-id": "client-456",
      "txma-audit-encoded": "audit-789",
      "x-forwarded-for": "192.168.1.1",
      "user-language": "en",
    });

    const result = validateRequiredHeaders(event);

    expect(result).to.equal(null);
  });

  it("should match headers case insensitively", () => {
    const event = createTestEvent(HttpMethod.GET, "/test", null, null, {
      "Di-Persistent-Session-Id": "persistent-session-123",
      "Session-id": "session-456",
      "Client-Session-Id": "client-456",
      "Txma-Audit-Encoded": "audit-789",
      "X-Forwarded-For": "192.168.1.1",
      "User-Language": "en",
    });

    const result = validateRequiredHeaders(event);

    expect(result).to.equal(null);
  });

  it("should return 400 error when di-persistent-session-id is missing", () => {
    const event = createTestEvent(HttpMethod.GET, "/test", null, null, {
      "session-id": "session-123",
      "client-session-id": "client-456",
      "txma-audit-encoded": "audit-789",
      "X-Forwarded-For": "192.168.1.1",
      "user-language": "en",
    });

    const result = validateRequiredHeaders(event);

    expect(result?.statusCode).to.eq(400);
    expect(result?.body).to.eq(
      "Missing required headers: di-persistent-session-id"
    );
  });

  it("should return 400 error when multiple headers are missing", () => {
    const event = createTestEvent(HttpMethod.GET, "/test", null, null, {
      "di-persistent-session-id": "session-123",
    });

    const result = validateRequiredHeaders(event);

    expect(result?.statusCode).to.eq(400);
    expect(result?.body).to.eq(
      "Missing required headers: client-session-id, session-id, x-forwarded-for, user-language"
    );
  });

  it("should return 400 error when all headers are missing", () => {
    const event = createTestEvent(HttpMethod.GET, "/test", null, null, {});

    const result = validateRequiredHeaders(event);

    expect(result?.statusCode).to.eq(400);
    expect(result?.body).to.eq(
      "Missing required headers: di-persistent-session-id, client-session-id, session-id, x-forwarded-for, user-language"
    );
  });
});
