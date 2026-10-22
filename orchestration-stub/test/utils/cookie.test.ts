import { expect } from "chai";
import { describe, it, afterEach } from "mocha";
import {
  getCookie,
  getOrCreatePersistentSessionId,
} from "../../src/utils/cookie";

describe("cookie.ts", () => {
  const originalCookieDomain = process.env.COOKIE_DOMAIN;

  afterEach(() => {
    if (originalCookieDomain === undefined) {
      delete process.env.COOKIE_DOMAIN;
    } else {
      process.env.COOKIE_DOMAIN = originalCookieDomain;
    }
  });

  [
    ["cookie1=somecookie; cookie2=anothercookie", "cookie2", "anothercookie"],
    ["cookie1=somecookie; ", "cookie1", "somecookie"],
  ].forEach(([cookies, name, expected]) => {
    it(`should get the cookie ${name}`, () => {
      expect(getCookie(cookies, name)).to.eq(expected);
    });
  });

  it("should return undefined when the cookie header is undefined", () => {
    expect(getCookie(undefined, "anything")).to.eq(undefined);
  });

  it("should return undefined when the named cookie is not present", () => {
    expect(getCookie("cookie1=somecookie", "missing")).to.eq(undefined);
  });

  it("should prefer the cookie for the current domain", () => {
    process.env.COOKIE_DOMAIN = "something.authdev.example.com";

    const cookies = "cookie=dev-cookie; cookie=authdev-cookie";

    expect(getCookie(cookies, "cookie")).to.eq("authdev-cookie");
  });

  it("should return the first cookie when the domain is not an authdev domain", () => {
    process.env.COOKIE_DOMAIN = "account.gov.uk";

    const cookies = "cookie=first-cookie; cookie=second-cookie";

    expect(getCookie(cookies, "cookie")).to.eq("first-cookie");
  });

  describe("getOrCreatePersistentSessionId", () => {
    it("should return the existing persistent session id from the cookie header", () => {
      const headers = {
        cookie: "di-persistent-session-id=existing-session-value",
      };

      expect(getOrCreatePersistentSessionId(headers)).to.eq(
        "existing-session-value",
      );
    });

    it("should create a new persistent session id when none exists", () => {
      const result = getOrCreatePersistentSessionId({});

      // Generated ids are of the form `<base64url>--<timestamp>`
      expect(result).to.match(/^[A-Za-z0-9_-]+--\d+$/);
    });

    it("should generate a unique id on each call when none exists", () => {
      const first = getOrCreatePersistentSessionId({});
      const second = getOrCreatePersistentSessionId({});

      expect(first).to.not.eq(second);
    });
  });
});
