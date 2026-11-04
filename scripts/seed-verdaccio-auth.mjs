import bcrypt from "bcryptjs";
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

const target = fileURLToPath(new URL("../verdaccio/htpasswd", import.meta.url));
const password = process.env.VERDACCIO_PASSWORD ?? "dev-service-token";
const username = process.env.VERDACCIO_USER ?? "gateway";

if (password.length < 8) {
  console.error("VERDACCIO_PASSWORD must be at least 8 characters.");
  process.exit(1);
}

mkdirSync(dirname(target), { recursive: true });
const hash = bcrypt.hashSync(password, 10);
// Verdaccio runs as uid 10001 in its container and reads this bind mount as a
// non-root user. 0644 keeps the dev file readable; production should use a
// secret mount with explicit ownership instead.
writeFileSync(target, `${username}:${hash}\n`, { mode: 0o644 });
chmodSync(target, 0o644);
console.log(`Wrote Verdaccio htpasswd for user "${username}" to ${target}`);
