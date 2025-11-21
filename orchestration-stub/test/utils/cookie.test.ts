import { getCookie } from "../../src/utils/cookie";

describe("cookie.ts", () => {
  it.each([
    ["cookie1=somecookie; cookie2=anothercookie", "cookie2", "anothercookie"],
    ["cookie1=somecookie; ", "cookie1", "somecookie"],
  ])("should get the cookie", (cookies, name, expected) => {
    const result = getCookie(cookies, name);

    expect(result).toEqual(expected);
  });

  it("should prefer the cookie for the current domain", () => {
    process.env.COOKIE_DOMAIN = "something.authdev.example.com";

    const cookies = "cookie=dev-cookie; cookie=authdev-cookie";
    const result = getCookie(cookies, "cookie");

    expect(result).toEqual("authdev-cookie");
  });
});
