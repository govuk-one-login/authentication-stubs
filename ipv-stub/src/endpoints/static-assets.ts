import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

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
