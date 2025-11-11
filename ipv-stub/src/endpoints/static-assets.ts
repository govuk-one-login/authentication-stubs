import { readFileSync } from "fs";
import { join } from "path";

export function serveStaticAsset(assetPath: string) {
  const filePath = join(__dirname, "../assets", assetPath);
  const content = readFileSync(filePath, "utf8");

  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/javascript",
      "Cache-Control": "public, max-age=31536000",
    },
    body: content,
  };
}
