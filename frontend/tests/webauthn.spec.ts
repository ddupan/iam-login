import { createHmac } from "node:crypto";
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
    await expect(page).toHaveURL(/\/signin\/mfa$/);
  }
  await login();
  await page.getByRole("button", { name: "创建 Passkey", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Passkey 已创建", exact: true })).toBeVisible();
  await page.goto("https://localhost:18083/signin/complete");
  await expect(page).toHaveURL(/^https:\/\/localhost:18083\/signin\/mfa(?:\?.*)?$/);
  const enrollmentToken = await page.evaluate(() => JSON.parse(document.getElementById("login-context")!.textContent!).csrf);
  const enrollAgain = await context.request.post("https://localhost:18083/webauthn/register/options", {
    headers: { [enrollmentToken.headerName]: enrollmentToken.value }, maxRedirects: 0,
  });
  expect(enrollAgain.status()).toBe(302);
  expect(enrollAgain.headers().location).toContain("factor.type=webauthn");
  const beforeMfa = (await context.cookies()).find(c => c.name === "SESSION")!.value;
  await page.getByRole("button", { name: "用 Passkey 验证", exact: true }).click();
  await expect(page.getByRole("heading", { name: "我的账户", exact: true })).toBeVisible();
  await expect(page.getByText("gitea-admins", { exact: true })).toBeVisible();
  expect((await context.cookies()).find(c => c.name === "SESSION")!.value).not.toBe(beforeMfa);
  await page.getByRole("button", { name: "退出", exact: true }).click();
  await login();
  await expect(page.getByRole("button", { name: "创建 Passkey", exact: true })).toHaveCount(0);
  const assertionRequest = page.waitForRequest(request => new URL(request.url()).pathname === "/login/webauthn");
  await page.getByRole("button", { name: "用 Passkey 验证", exact: true }).click();
  const assertion = (await assertionRequest).postDataJSON();
  await expect(page.getByRole("heading", { name: "我的账户", exact: true })).toBeVisible();
  const token = await page.evaluate(() => JSON.parse(document.getElementById("login-context")!.textContent!).csrf);
  const replay = await context.request.post("https://localhost:18083/login/webauthn", {
    headers: { [token.headerName]: token.value }, data: assertion,
  });
  expect(replay.status()).toBe(401);
  // Passwordless: the same passkey is the whole sign-in, no password typed; the visit resumes where it started.
  await page.getByRole("button", { name: "退出", exact: true }).click();
  await page.goto("https://localhost:18083/account");
  await expect(page).toHaveURL(/\/signin$/);
  await page.getByRole("button", { name: "使用 Passkey 登录", exact: true }).click();
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.getByRole("heading", { name: "我的账户", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "退出", exact: true }).click();
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

// Account page: list, rename, add a second passkey, and the last one cannot be removed. Uses bob, who has none yet.
test("account page manages the account's own passkeys", async ({ page, context }) => {
  test.skip(process.env.IAM_WEBAUTHN_FIXTURE !== "1", "Start the test-only webauthnBrowserFixture first");
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const options = { protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } as const;
  const { authenticatorId: first } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options });
  await page.goto("https://localhost:18083/account");
  await expect(page).toHaveURL(/\/signin$/);
  await page.getByLabel("用户名", { exact: true }).fill("bob");
  await page.getByLabel("密码", { exact: true }).fill("fixture-password");
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await page.getByRole("button", { name: "创建 Passkey", exact: true }).click();
  await page.getByRole("button", { name: "用 Passkey 验证", exact: true }).click();
  // Resumed where the visit started.
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.getByRole("heading", { name: "我的账户", exact: true })).toBeVisible();
  const passkeys = page.getByRole("region", { name: "Passkey" }).getByRole("listitem");
  await expect(passkeys).toHaveCount(1);
  await expect(passkeys.getByRole("button", { name: "删除", exact: true })).toBeDisabled();

  await passkeys.getByRole("button", { name: "改名", exact: true }).click();
  await page.getByRole("dialog").getByLabel("名称", { exact: true }).fill("旧电脑");
  await page.getByRole("dialog").getByRole("button", { name: "保存", exact: true }).click();
  await expect(passkeys.getByText("旧电脑", { exact: true })).toBeVisible();

  // A second authenticator: the first already holds bob's credential and is excluded from registration.
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: first });
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options });
  await page.getByRole("button", { name: "添加 Passkey", exact: true }).click();
  await expect(passkeys).toHaveCount(2);

  await passkeys.filter({ hasText: "旧电脑" }).getByRole("button", { name: "删除", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "删除", exact: true }).click();
  await expect(passkeys).toHaveCount(1);
  await expect(page.getByText("旧电脑", { exact: true })).toHaveCount(0);
  await expect(passkeys.getByRole("button", { name: "删除", exact: true })).toBeDisabled();

  // An authenticator app as the other second factor: then the last passkey may go, and sign-in asks for a code.
  await page.getByRole("link", { name: "设置验证器 App", exact: true }).click();
  await expect(page.getByRole("img", { name: "验证器 App 的二维码" })).toBeVisible();
  const secret = (await page.locator("code.secret").textContent())!.replaceAll(" ", "");
  const step = Math.floor(Date.now() / 30000);
  await page.getByLabel("验证码", { exact: true }).fill(totp(secret, step));
  await page.getByRole("button", { name: "确认并启用", exact: true }).click();
  await expect(page).toHaveURL(/\/account$/);
  const authenticator = page.getByRole("region", { name: "验证器 App" });
  await expect(authenticator.getByText("已设置", { exact: true })).toBeVisible();
  await passkeys.getByRole("button", { name: "删除", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "删除", exact: true }).click();
  await expect(passkeys).toHaveCount(0);
  await expect(authenticator.getByRole("button", { name: "删除", exact: true })).toBeDisabled();

  await page.getByRole("button", { name: "退出", exact: true }).click();
  await page.getByLabel("用户名", { exact: true }).fill("bob");
  await page.getByLabel("密码", { exact: true }).fill("fixture-password");
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await expect(page.getByRole("heading", { name: "输入验证码", exact: true })).toBeVisible();
  // The code that confirmed the set-up is spent; the next step's is still within the allowed drift.
  await page.getByLabel("验证码", { exact: true }).fill(totp(secret, step));
  await page.getByRole("button", { name: "验证", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("验证码不对或已用过");
  await page.getByLabel("验证码", { exact: true }).fill(totp(secret, step + 1));
  await page.getByRole("button", { name: "验证", exact: true }).click();
  await expect(page.getByRole("heading", { name: "我的账户", exact: true })).toBeVisible();
});

/** RFC 6238 (HMAC-SHA1, 6 digits) from the base32 key the set-up page shows. */
function totp(base32: string, step: number) {
  let bits = "";
  for (const c of base32) bits += "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g)!.map(b => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const hash = createHmac("sha1", key).update(counter).digest();
  const offset = hash[hash.length - 1] & 0xf;
  return String((hash.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}
