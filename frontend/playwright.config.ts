import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests",
  use: {
    baseURL: process.env.IAM_PREVIEW_URL ?? "http://127.0.0.1:18081",
    headless: true,
  },
});
