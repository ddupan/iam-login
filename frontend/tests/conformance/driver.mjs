// Spike tooling: drives the OpenID conformance suite's front-channel steps with a real browser, in place of
// the suite's HtmlUnit runner (which cannot run our ES-module login page, nor WebAuthn). One browser context
// for the whole run: the first login registers a passkey on a virtual authenticator, later ones use it.
// Runs until the file named by STOP_FILE exists. Test-only; points at loopback fixtures.
import { chromium } from "@playwright/test";
import { existsSync } from "node:fs";

const SUITE = process.env.CONFORMANCE_SERVER ?? "https://localhost.emobix.co.uk:8443";
const OP = process.env.OP_ORIGIN ?? "https://localhost:18083";
const STOP = process.env.STOP_FILE ?? "/c/stop-driver";
const log = (...args) => console.log(new Date().toISOString(), ...args);

const browser = await chromium.launch();
const context = await browser.newContext({ ignoreHTTPSErrors: true, locale: "zh-CN" });
const page = await context.newPage();
const cdp = await context.newCDPSession(page);
await cdp.send("WebAuthn.enable");
await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
  protocol: "ctap2", transport: "internal", hasResidentKey: true,
  hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
} });
const api = await (await import("@playwright/test")).request.newContext({ ignoreHTTPSErrors: true, baseURL: SUITE });

async function drive(escaped) {
  // The suite's browser API returns URLs HTML-escaped ("&amp;"); unescaped, parameters such as nonce would
  // reach the OP as "amp;nonce" and every test would fail for reasons that are not the OP's.
  const url = escaped.replaceAll("&amp;", "&");
  await page.goto(url).catch(error => log("goto failed", error.message));
  for (let step = 0; step < 20; step++) {
    await page.waitForLoadState("load").catch(() => {});
    const here = page.url();
    if (here.startsWith(SUITE)) {
      // The suite's callback page reports back and shows #submission_complete.
      await page.locator("#submission_complete").waitFor({ timeout: 10000 }).catch(() => log("no submission_complete", here));
      return;
    }
    if (!here.startsWith(OP)) { log("left OP to", here); return; }
    const has = name => page.getByRole("button", { name, exact: true }).isVisible().catch(() => false);
    if (await page.getByRole("heading", { name: "登录", exact: true }).isVisible().catch(() => false)) {
      await page.getByLabel("用户名", { exact: true }).fill("alice");
      await page.getByLabel("密码", { exact: true }).fill("fixture-password");
      await page.getByRole("button", { name: "继续", exact: true }).click();
    } else if (await has(/^创建 passkey$/i)) {
      await page.getByRole("button", { name: /^创建 passkey$/i }).click();
      await page.getByRole("button", { name: /^用 passkey 验证$/i }).waitFor({ timeout: 10000 }).catch(() => {});
    } else if (await has(/^用 passkey 验证$/i)) {
      await page.getByRole("button", { name: /^用 passkey 验证$/i }).click();
    } else if (await has("允许")) {
      await page.getByRole("button", { name: "允许", exact: true }).click();
    } else {
      // An OP error page is a legitimate outcome for negative tests; the suite then asks for review.
      log("OP page needs no action", here);
      return;
    }
    await page.waitForURL(u => u.toString() !== here, { timeout: 10000 }).catch(() => {});
  }
}

log("driver started");
// Each test module starts from a logged-out browser, as the suite's own runner does; within a module the
// session persists (e.g. prompt=none after a login). The passkey lives in the authenticator, not cookies.
const started = new Set();
while (!existsSync(STOP)) {
  const running = await api.get("/api/runner/running").then(r => r.ok() ? r.json() : []).catch(() => []);
  for (const id of running) {
    const state = await api.get(`/api/runner/browser/${id}`).then(r => r.ok() ? r.json() : null).catch(() => null);
    for (const url of state?.urls?.filter(u => !state.visited.includes(u)) ?? []) {
      if (!started.has(id)) { started.add(id); await context.clearCookies(); }
      await api.post(`/api/runner/browser/${id}/visit?url=${encodeURIComponent(url)}`);
      log(id, "visit", url.slice(0, 120));
      await drive(url);
    }
  }
  await new Promise(resolve => setTimeout(resolve, 1000));
}
await browser.close();
log("driver stopped");
