import "dotenv/config";
import { createServer } from "./server";
const PORT = process.env.PORT ?? 3000;

async function main() {
  const app = await createServer();
  app.listen(PORT, () => {
    console.log(`Auth service running on http://localhost:${PORT}`);
  });
}

main().catch((err) => {
  console.error("Failed to start", err);
  process.exit(1);
});
