import { test, expect } from "@playwright/test";

test.use({ ignoreHTTPSErrors: true });

// Dedicated localhost fixture only. Never registers a synthetic credential against real AD.
test("AD + PostgreSQL + real WebAuthn ceremony, factor gating and persisted re-login", async ({ page, context }) => {
  test.skip(process.env.IAM_WEBAUTHN_FIXTURE !== "1", "Start the test-only webauthnBrowserFixture first");
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });
  async function login(username = "alice") {
    await page.goto("https://localhost:18083/signin");
    await page.getByLabel("用户名", { exact: true }).fill(username);
    await page.getByLabel("密码", { exact: true }).fill("fixture-password");
    await page.getByRole("button", { name: "继续", exact: true }).click();
    await expect(page.getByRole("heading", { name: "密码已验证，等待 MFA" })).toBeVisible();
  }
  await login();
  await page.getByRole("button", { name: "注册 Passkey", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Passkey 已保存");
  await page.goto("https://localhost:18083/signin/complete");
  await expect(page).toHaveURL(/^https:\/\/localhost:18083\/signin\/mfa(?:\?.*)?$/);
  const enrollmentToken = await page.evaluate(() => JSON.parse(document.getElementById("login-context")!.textContent!).csrf);
  const enrollAgain = await context.request.post("https://localhost:18083/webauthn/register/options", {
    headers: { [enrollmentToken.headerName]: enrollmentToken.value }, maxRedirects: 0,
  });
  expect(enrollAgain.status()).toBe(302);
  expect(enrollAgain.headers().location).toContain("factor.type=webauthn");
  const beforeMfa = (await context.cookies()).find(c => c.name === "JSESSIONID")!.value;
  await page.getByRole("button", { name: "验证 Passkey", exact: true }).click();
  await expect(page.getByRole("heading", { name: "MFA 已验证", exact: true })).toBeVisible();
  await expect(page.getByText("gitea-admins", { exact: true })).toBeVisible();
  expect((await context.cookies()).find(c => c.name === "JSESSIONID")!.value).not.toBe(beforeMfa);
  await page.getByRole("button", { name: "退出并重新验证", exact: true }).click();
  await login();
  await expect(page.getByRole("button", { name: "注册 Passkey", exact: true })).toHaveCount(0);
  const assertionRequest = page.waitForRequest(request => new URL(request.url()).pathname === "/login/webauthn");
  await page.getByRole("button", { name: "验证 Passkey", exact: true }).click();
  const assertion = (await assertionRequest).postDataJSON();
  await expect(page.getByRole("heading", { name: "MFA 已验证", exact: true })).toBeVisible();
  const token = await page.evaluate(() => JSON.parse(document.getElementById("login-context")!.textContent!).csrf);
  const replay = await context.request.post("https://localhost:18083/login/webauthn", {
    headers: { [token.headerName]: token.value }, data: assertion,
  });
  expect(replay.status()).toBe(401);
  await page.getByRole("button", { name: "退出并重新验证", exact: true }).click();
  await login("bob");
  // Bob has no credential. A discoverable Alice credential must not become Bob's second factor.
  const foreignStatus = await page.evaluate(async () => {
    const csrf = JSON.parse(document.getElementById("login-context")!.textContent!).csrf;
    const headers = { "Content-Type": "application/json", [csrf.headerName]: csrf.value };
    const options = await fetch("/webauthn/authenticate/options", { method: "POST", headers }).then(r => r.json());
    const credential = await navigator.credentials.get({
      publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
    }) as PublicKeyCredential;
    return fetch("/login/webauthn", { method: "POST", headers, body: JSON.stringify(credential.toJSON()) })
      .then(r => r.status);
  });
  expect(foreignStatus).toBe(401);
});
