import { expect } from "chai";
import { after, before, describe, it } from "mocha";
import { mkdirSync, rmSync, writeFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { serveStaticAsset } from "../../src/endpoints/static-assets";

const testFileDir = dirname(fileURLToPath(import.meta.url));
// test/endpoints -> stub root -> src/assets (matches static-assets.ts resolution)
const assetsDir = join(testFileDir, "..", "..", "src", "assets");

describe("static-assets endpoint", () => {
  before(() => {
    mkdirSync(assetsDir, { recursive: true });
    writeFileSync(join(assetsDir, "test-asset.js"), "console.log('hi');");
  });

  after(() => {
    rmSync(assetsDir, { recursive: true, force: true });
  });

  it("should serve an existing asset with javascript content type and caching", () => {
    const result = serveStaticAsset("test-asset.js");

    expect(result.statusCode).to.eq(200);
    expect(result.headers["Content-Type"]).to.eq("application/javascript");
    expect(result.headers["Cache-Control"]).to.eq("public, max-age=31536000");
    expect(result.body).to.eq("console.log('hi');");
  });

  it("should throw when the asset does not exist", () => {
    expect(() => serveStaticAsset("does-not-exist.js")).to.throw();
  });
});
