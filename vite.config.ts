import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { env } from "node:process";

const rootDir = fileURLToPath(new URL("./", import.meta.url));
const host = env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async () => {
  const version = env.npm_package_version ?? "0.0.0";

  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        "@": resolve(rootDir, "./src"),
      },
    },

    css: {
      devSourcemap: true,
    },

    define: {
      __APP_VERSION__: JSON.stringify(version),
    },

    // Vite options tailored for Tauri development and only applied in 	auri dev or 	auri build
    //
    // 1. prevent Vite from obscuring rust errors
    clearScreen: false,
    // 2. tauri expects a fixed port, fail if that port is not available
    server: {
      port: 1420,
      strictPort: true,
      host: host || false,
      hmr: {
        port: host ? 1421 : undefined,
        protocol: host ? "ws" : undefined,
        host: host || undefined,
        overlay: true,
      },
      watch: {
        // 3. tell Vite to ignore watching src-tauri
        ignored: ["**/src-tauri/**"],
      },
    },
  };
});
