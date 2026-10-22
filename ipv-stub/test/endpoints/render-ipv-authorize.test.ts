import { expect } from "chai";
import { describe, it } from "mocha";
import renderIPVAuthorize from "../../src/endpoints/render-ipv-authorize";
import { DecodedRequest } from "../../src/helper/types";

describe("render-ipv-authorize", () => {
  const payload = {
    sub: "test-sub",
    scope: "reverification",
    state: "test-state",
    redirect_uri: "https://rp.example.com/callback",
    claims: { userinfo: {} },
  } as unknown as DecodedRequest;

  it("should render the decoded header algorithm", () => {
    const html = renderIPVAuthorize("ES256", payload);

    expect(html).to.contain("IPV stub");
    expect(html).to.contain("ES256");
  });

  it("should embed the payload values into the hidden form fields", () => {
    const html = renderIPVAuthorize("ES256", payload);

    expect(html).to.contain('name="state" value=test-state');
    expect(html).to.contain('name="sub" value=test-sub');
    expect(html).to.contain(
      'name="redirect_uri" value=https://rp.example.com/callback'
    );
  });

  it("should render a cross-browser test link using redirect_uri and state", () => {
    const html = renderIPVAuthorize("ES256", payload);

    expect(html).to.contain(
      "https://rp.example.com/callback?state=test-state&error=access_denied"
    );
  });

  it("should render the IPV response radio options", () => {
    const html = renderIPVAuthorize("ES256", payload);

    expect(html).to.contain('value="success"');
    expect(html).to.contain('value="no_identity_available"');
    expect(html).to.contain('value="identity_check_failed"');
  });
});
