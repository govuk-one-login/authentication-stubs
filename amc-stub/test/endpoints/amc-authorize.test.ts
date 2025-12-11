import { expect } from "chai";
import { handler } from "../../src/endpoints/amc-authorize.js";
import { createTestEvent } from "../test-helpers.js";
import { HttpMethod } from "../../src/types/enums.js";

describe("AMC Authorize Stub Test", () => {
  it("should call GET", async () => {
    const event = createTestEvent(HttpMethod.GET);

    const result = await handler(event);

    expect(result.statusCode).to.eq(200);
    expect(result.body).to.eq(JSON.stringify({ message: "Great success" }));
  });

  it("should call POST", async () => {
    const event = createTestEvent(HttpMethod.POST);

    const result = await handler(event);

    expect(result.statusCode).to.eq(200);
    expect(result.body).to.eq(
      JSON.stringify({ message: "To be implemented as part of AUT-5006" })
    );
  });

  const unsupportedMethods = [HttpMethod.PUT, HttpMethod.DELETE];
  unsupportedMethods.forEach((method) => {
    it(`should not allow ${method}`, async () => {
      const event = createTestEvent(method);

      try {
        await handler(event);
        expect.fail("Should have thrown an error");
      } catch (error: unknown) {
        expect(error).to.be.instanceOf(Error);
        expect((error as { code: number }).code).to.eq(405);
      }
    });
  });
});
