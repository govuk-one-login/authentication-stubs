import { expect } from "chai";
import { truncate } from "../../src/helpers/truncate-helper.ts";

describe("truncate", () => {
  it("should return 'obfuscated' for values with 10 or fewer characters", () => {
    expect(truncate("short")).to.eq("obfuscated");
    expect(truncate("1234567890")).to.eq("obfuscated");
  });

  it("should truncate values longer than 10 characters", () => {
    expect(truncate("12345678901")).to.eq("123...901");
    expect(truncate("verylongvalue")).to.eq("ver...lue");
  });

  it("should handle empty string", () => {
    expect(truncate("")).to.eq("obfuscated");
  });
});
