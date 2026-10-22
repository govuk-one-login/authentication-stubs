import { expect } from "chai";
import { describe, it } from "mocha";
import { parseRequestParameters } from "../../src/services/request-parameters";
import { ChannelEnum } from "../../src/types/channel";

describe("request-parameters.ts", () => {
  describe("parseRequestParameters", () => {
    it("should throw when the body is null", () => {
      expect(() => parseRequestParameters(null)).to.throw("No body");
    });

    it("should parse a minimal valid Cl body", () => {
      const result = parseRequestParameters("level=Cl&channel=web");

      expect(result).to.deep.eq({
        confidence: "Cl",
        reauthenticate: undefined,
        authenticated: false,
        channel: ChannelEnum.WEB,
        cookieConsent: undefined,
      });
    });

    it("should parse a Cl.Cm confidence level", () => {
      const result = parseRequestParameters("level=Cl.Cm&channel=none");

      expect(result.confidence).to.eq("Cl.Cm");
      expect(result.channel).to.eq(ChannelEnum.NONE);
    });

    it("should set authenticated to true only when the value is 'yes'", () => {
      expect(
        parseRequestParameters("level=Cl&channel=web&authenticated=yes")
          .authenticated,
      ).to.eq(true);
      expect(
        parseRequestParameters("level=Cl&channel=web&authenticated=no")
          .authenticated,
      ).to.eq(false);
    });

    it("should capture reauthenticate when it is a non-empty string", () => {
      const result = parseRequestParameters(
        "level=Cl&channel=web&reauthenticate=some-pairwise-id",
      );

      expect(result.reauthenticate).to.eq("some-pairwise-id");
    });

    it("should treat an empty reauthenticate value as undefined", () => {
      const result = parseRequestParameters(
        "level=Cl&channel=web&reauthenticate=",
      );

      expect(result.reauthenticate).to.eq(undefined);
    });

    it("should pass through cookie-consent", () => {
      const result = parseRequestParameters(
        "level=Cl&channel=web&cookie-consent=accept",
      );

      expect(result.cookieConsent).to.eq("accept");
    });

    [
      ChannelEnum.NONE,
      ChannelEnum.WEB,
      ChannelEnum.STRATEGIC_APP,
      ChannelEnum.GENERIC_APP,
    ].forEach((channel) => {
      it(`should accept the valid channel ${channel}`, () => {
        const result = parseRequestParameters(`level=Cl&channel=${channel}`);

        expect(result.channel).to.eq(channel);
      });
    });

    it("should throw on an unknown credential trust level", () => {
      expect(() => parseRequestParameters("level=Cx&channel=web")).to.throw(
        "Unknown level Cx",
      );
    });

    it("should throw when the level is missing", () => {
      expect(() => parseRequestParameters("channel=web")).to.throw(
        "Unknown level undefined",
      );
    });

    it("should throw on an unknown channel", () => {
      expect(() =>
        parseRequestParameters("level=Cl&channel=carrier-pigeon"),
      ).to.throw("Unknown channel: carrier-pigeon");
    });

    it("should throw when the channel is missing", () => {
      expect(() => parseRequestParameters("level=Cl")).to.throw(
        "Unknown channel: undefined",
      );
    });
  });
});
