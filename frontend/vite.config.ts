import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the Vite server proxies the API routes to the local API
// (`threatweave demo`, port 8000), so the app calls same-origin `/api/*` in both
// dev and production (where FastAPI serves the built bundle from the same origin).
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": "http://localhost:8000",
      "/health": "http://localhost:8000",
    },
  },
  build: {
    outDir: "dist",
  },
});
