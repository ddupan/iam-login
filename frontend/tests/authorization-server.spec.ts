import { test, expect } from "@playwright/test";
import { createServer, type Server } from "node:http";
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";

// Spike: the in-process authorization server, end to end with a real (virtual) WebAuthn authenticator.
test.use({ ignoreHTTPSErrors: true });
const ISSUER = "https://localhost:18083";
const CALLBACK = "http://localhost:14446/callback";
let callbackServer: Server | undefined;
test.beforeAll(async () => {
  if (process.env.IAM_AUTHORIZATION_SERVER_FIXTURE !== "1") return;
  callbackServer = createServer((request, response) => {
    response.writeHead(request.url?.startsWith("/callback?") || request.url === "/logged-out" ? 200 : 404, { "Content-Type": "text/html" });
    response.end("Fixture callback");
  });
  await new Promise<void>(resolve => callbackServer!.listen(14446, "127.0.0.1", resolve));
});
test.afterAll(async () => {
  if (callbackServer) await new Promise<void>((resolve, reject) => callbackServer!.close(error => error ? reject(error) : resolve()));
});

test("AD + passkey -> in-process authorization server: consent, tokens, userinfo, refresh, logout", async ({ page, context }) => {
  test.skip(process.env.IAM_AUTHORIZATION_SERVER_FIXTURE !== "1", "Start authorizationServerBrowserFixture; never runs against production");
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });
  const discovery = await context.request.get(`${ISSUER}/.well-known/openid-configuration`).then(r => r.json());
  expect(discovery.issuer).toBe(ISSUER);
  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(24).toString("base64url");
  const nonce = randomBytes(24).toString("base64url");
  const authorize = new URL(discovery.authorization_endpoint);
  authorize.search = new URLSearchParams({ client_id: "fixture-rp", response_type: "code", redirect_uri: CALLBACK,
    scope: "openid profile email groups offline_access", state, nonce,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256",
  }).toString();

  await page.goto(authorize.toString());
  await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();
  await page.getByLabel("用户名", { exact: true }).fill("alice");
  await page.getByLabel("密码", { exact: true }).fill("fixture-password");
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await page.getByRole("button", { name: "创建 Passkey", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Passkey 已创建", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "用 Passkey 验证", exact: true }).click();
  // Resumed authorization request -> our consent page: requested access in plain words, then allow.
  await expect(page.getByRole("heading", { name: /请求访问你的账号$/ })).toBeVisible();
  await expect(page.getByText("你所在的组", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "允许", exact: true }).click();
  await expect.poll(() => new URL(page.url()).origin + new URL(page.url()).pathname).toBe(CALLBACK);
  const callback = new URL(page.url());
  expect(callback.searchParams.get("state")).toBe(state);
  const basic = { Authorization: "Basic " + Buffer.from("fixture-rp:fixture-client-secret").toString("base64") };
  const exchange = await context.request.post(discovery.token_endpoint, { headers: basic,
    form: { grant_type: "authorization_code", code: callback.searchParams.get("code")!, redirect_uri: CALLBACK, code_verifier: verifier } });
  expect(exchange.status()).toBe(200);
  const tokens = await exchange.json();

  const [h, p, s] = tokens.id_token.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url").toString());
  const keys = await context.request.get(discovery.jwks_uri).then(r => r.json());
  const jwk = keys.keys.find((key: { kid: string }) => key.kid === header.kid);
  expect(verify("RSA-SHA256", Buffer.from(h + "." + p), createPublicKey({ key: jwk, format: "jwk" }), Buffer.from(s, "base64url"))).toBe(true);
  const claims = JSON.parse(Buffer.from(p, "base64url").toString());
  expect(claims).toMatchObject({ iss: ISSUER, sub: "human:fixture-existing-oidc-subject", nonce,
    preferred_username: "alice", email: "alice@example.test", email_verified: false });
  expect([claims.aud].flat()).toContain("fixture-rp");
  expect(claims.groups).toEqual(expect.arrayContaining(["gitea-admins"]));

  const userinfo = await context.request.get(discovery.userinfo_endpoint, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
  expect(userinfo.status()).toBe(200);
  expect((await userinfo.json()).sub).toBe("human:fixture-existing-oidc-subject");

  expect(tokens.refresh_token).toBeTruthy();
  const refresh = (token: string) => context.request.post(discovery.token_endpoint, { headers: basic, form: { grant_type: "refresh_token", refresh_token: token } });
  const renewed = await refresh(tokens.refresh_token);
  expect(renewed.status()).toBe(200);
  const latest = await renewed.json();
  expect(latest.refresh_token).not.toBe(tokens.refresh_token);
  expect((await refresh(tokens.refresh_token)).status()).toBe(400);

  // RP-initiated logout ends the login session at the issuer. Refresh replaced the ID token, so the
  // hint must be the latest one (the framework looks the authorization up by it).
  const logout = new URL(discovery.end_session_endpoint);
  logout.search = new URLSearchParams({ id_token_hint: latest.id_token, post_logout_redirect_uri: "http://localhost:14446/logged-out" }).toString();
  await page.goto(logout.toString());
  await expect.poll(() => new URL(page.url()).origin + new URL(page.url()).pathname).toBe("http://localhost:14446/logged-out");
  await page.goto(authorize.toString());
  await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();

  // Console: a public client of this same server; the client API only accepts its bearer token.
  expect((await context.request.get(`${ISSUER}/api/iam/clients`, { headers: { Authorization: `Bearer ${latest.access_token}` } })).status()).toBe(403);
  await page.goto(`${ISSUER}/console`);
  await page.getByLabel("用户名", { exact: true }).fill("alice");
  await page.getByLabel("密码", { exact: true }).fill("fixture-password");
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await page.getByRole("button", { name: "用 Passkey 验证", exact: true }).click();
  await expect(page.getByRole("heading", { name: "OIDC 客户端" })).toBeVisible();
  expect(new URL(page.url()).pathname).toBe("/console");
  await expect(page.getByRole("row", { name: /fixture-rp/ })).toBeVisible();
  // The console's own (public) client is not a managed client.
  await expect(page.getByRole("cell", { name: "iam-console", exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "新建客户端", exact: true }).click();
  await page.getByLabel("Client ID").fill("e2e-app");
  await page.getByLabel("名称").fill("E2E");
  await page.getByLabel("回调地址（每行一个）").fill("https://app.example.test/callback");
  await page.getByRole("button", { name: "创建", exact: true }).click();
  const secret = page.locator(".secret output");
  await expect(secret).not.toBeEmpty();
  const created = (await secret.textContent())!;
  page.once("dialog", dialog => dialog.accept());
  await page.getByRole("row", { name: /e2e-app/ }).getByRole("button", { name: "轮换 secret" }).click();
  await expect(secret).not.toHaveText(created);
  const rotated = (await secret.textContent())!;
  const tokenError = (value: string) => context.request.post(discovery.token_endpoint, {
    headers: { Authorization: "Basic " + Buffer.from(`e2e-app:${value}`).toString("base64") },
    form: { grant_type: "authorization_code", code: "invalid-code", redirect_uri: "https://app.example.test/callback" },
  }).then(response => response.json()).then(body => body.error);
  expect(await tokenError(created)).toBe("invalid_client");
  expect(await tokenError(rotated)).not.toBe("invalid_client");
  page.once("dialog", dialog => dialog.accept());
  await page.getByRole("row", { name: /e2e-app/ }).getByRole("button", { name: "删除" }).click();
  await expect(page.getByRole("cell", { name: "e2e-app", exact: true })).toHaveCount(0);
});
