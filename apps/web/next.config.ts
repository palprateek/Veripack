import { config as loadEnv } from "dotenv";
import { resolve } from "node:path";
import type { NextConfig } from "next";

loadEnv({ path: resolve(process.cwd(), "../../.env"), quiet: true });
loadEnv({ quiet: true });

const nextConfig: NextConfig = {
  transpilePackages: ["@veripack/shared"],
  output: "standalone",
  outputFileTracingRoot: resolve(process.cwd(), "../.."),
};

export default nextConfig;
