import { expect } from "chai";
import { handler } from "../../src/endpoints/amc-journey-outcome.ts";
import { HttpMethod } from "../../src/types/enums.ts";
import { createTestEvent } from "../test-helpers.ts";

describe("AMC Journey Outcome Stub Test", () => {
  describe("GET handler", () => {
    it("should return 200 with HTML for valid GET request", async () => {
      const event = createTestEvent(HttpMethod.GET, "/journeyoutcome", null);

      const result = await handler(event);

      expect(result.statusCode).to.eq(200);
      expect(result.headers?.["Content-Type"]).to.eq("application/json");
    });
  });
});
