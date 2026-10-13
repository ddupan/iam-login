import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests",
  use: {
    baseURL: process.env.IAM_AD_URL,
    headless: true,
    // The pages follow the browser language; tests address controls by their zh-CN labels.
    locale: "zh-CN",
  },
});
