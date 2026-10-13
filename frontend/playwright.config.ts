import { defineConfig, devices } from "@playwright/test";

const python = process.platform === "win32" ? "../backend/.venv/Scripts/python.exe" : "../backend/.venv/bin/python";

export default defineConfig({
  testDir: "./e2e",
  timeout: 480_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: { baseURL: "http://127.0.0.1:5199", trace: "retain-on-failure", actionTimeout: 20_000, viewport: { width: 1440, height: 900 } },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"], ...(process.env.PW_CHANNEL ? { channel: process.env.PW_CHANNEL } : {}), viewport: { width: 1440, height: 900 } } }],
  webServer: [
    {
      command: `"${python}" ../backend/scripts/e2e_server.py 8099`,
      url: "http://127.0.0.1:8099/api/health",
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: "npm run build && npx vite preview --host 127.0.0.1 --port 5199 --strictPort",
      url: "http://127.0.0.1:5199",
      env: { THREATREADY_BACKEND: "http://127.0.0.1:8099", PORT: "5199" },
      reuseExistingServer: false,
      timeout: 180_000,
    },
  ],
});
