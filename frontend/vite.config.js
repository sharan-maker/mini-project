import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vite is free/open-source. Dev server runs on port 3000 to match
// the CORS allow_origins list in backend/app/main.py.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
  },
});