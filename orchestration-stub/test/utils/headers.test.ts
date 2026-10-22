import { expect } from "chai";
import { describe, it } from "mocha";
import { APIGatewayProxyEvent } from "aws-lambda";
import { downcaseHeaders } from "../../src/utils/headers";

const buildEvent = (
  headers: Record<string, string | undefined>,
): APIGatewayProxyEvent => ({ headers }) as unknown as APIGatewayProxyEvent;

describe("headers.ts", () => {
  describe("downcaseHeaders", () => {
    it("should add lowercase versions of mixed-case headers", () => {
      const event = buildEvent({
        "Content-Type": "application/json",
        "X-Custom-Header": "value",
      });

      downcaseHeaders(event);

      expect(event.headers["content-type"]).to.eq("application/json");
      expect(event.headers["x-custom-header"]).to.eq("value");
    });

    it("should preserve the original header casing", () => {
      const event = buildEvent({ "Content-Type": "application/json" });

      downcaseHeaders(event);

      expect(event.headers["Content-Type"]).to.eq("application/json");
    });

    it("should leave already-lowercase headers unchanged", () => {
      const event = buildEvent({ cookie: "a=b" });

      downcaseHeaders(event);

      expect(event.headers["cookie"]).to.eq("a=b");
    });

    it("should be idempotent and not re-process an already-fixed event", () => {
      const event = buildEvent({ "Content-Type": "application/json" });

      downcaseHeaders(event);
      // Mutating after the first call should have no effect on a second call
      // because the event is flagged as already fixed.
      event.headers["New-Header"] = "late";
      downcaseHeaders(event);

      expect(event.headers["new-header"]).to.eq(undefined);
    });

    it("should handle an empty headers object", () => {
      const event = buildEvent({});

      expect(() => downcaseHeaders(event)).to.not.throw();
      expect(event.headers).to.deep.eq({});
    });
  });
});
