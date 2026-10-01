import { test, expect } from "@playwright/test";
import { createServer, type Server } from "node:http";
import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";

test.use({ ignoreHTTPSErrors: true });
let callbackServer: Server | undefined;
const logoutTokens: string[] = [];
test.beforeAll(async () => {
  if (process.env.IAM_HYDRA_FIXTURE !== "1") return;
  callbackServer = createServer((request, response) => {
    if (request.url === "/backchannel" && request.method === "POST") {
      let body = "";
      request.on("data", chunk => { body += chunk.toString(); });
      request.on("end", () => {
        logoutTokens.push(new URLSearchParams(body).get("logout_token") ?? "");
        response.writeHead(200); response.end();
      });
      return;
    }
    response.writeHead(request.url?.startsWith("/callback?") || request.url === "/logged-out" ? 200 : 404, { "Content-Type": "text/html" });
    response.end("Fixture callback");
  });
  await new Promise<void>(resolve => callbackServer!.listen(14446, "127.0.0.1", resolve));
});
test.afterAll(async () => {
  if (callbackServer) await new Promise<void>((resolve, reject) => callbackServer!.close(error => error ? reject(error) : resolve()));
});

test("AD + passkey -> Hydra authorization code -> signed OIDC token and coordinated logout", async ({ page, context }) => {
  test.skip(process.env.IAM_HYDRA_FIXTURE !== "1", "Start hydraBrowserFixture; never runs against production");
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
  } });
  const verifier = randomBytes(32).toString("base64url");
  const state = randomBytes(24).toString("base64url");
  const nonce = randomBytes(24).toString("base64url");
  const authorize = new URL("http://localhost:14444/oauth2/auth");
  authorize.search = new URLSearchParams({ client_id: "gitea-fixture", response_type: "code",
    redirect_uri: "http://localhost:14446/callback", scope: "openid profile email groups", state, nonce,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"), code_challenge_method: "S256",
  }).toString();
  await page.goto(authorize.toString());
  await expect(page.getByRole("heading", { name: "登录你的账号" })).toBeVisible();
  await page.getByLabel("用户名", { exact: true }).fill("alice");
  await page.getByLabel("密码", { exact: true }).fill("fixture-password");
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await page.getByRole("button", { name: "注册 Passkey", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Passkey 已保存");
  await page.getByRole("button", { name: "验证 Passkey", exact: true }).click();
  await expect(page.getByRole("heading", { name: "继续登录 gitea-fixture" })).toBeVisible();
  await page.getByRole("button", { name: "继续至应用", exact: true }).click();
  await expect.poll(() => new URL(page.url()).origin + new URL(page.url()).pathname)
    .toBe("http://localhost:14446/callback");
  const callback = new URL(page.url());
  expect(callback.searchParams.get("state")).toBe(state);
  expect(callback.searchParams.has("error")).toBe(false);
  const code = callback.searchParams.get("code")!;
  expect(code).toBeTruthy();
  const exchange = await context.request.post("http://localhost:14444/oauth2/token", {
    headers: { Authorization: "Basic " + Buffer.from("gitea-fixture:fixture-client-secret").toString("base64") },
    form: { grant_type: "authorization_code", code, redirect_uri: "http://localhost:14446/callback", code_verifier: verifier },
  });
  expect(exchange.status()).toBe(200);
  const tokens = await exchange.json();
  expect(tokens.refresh_token).toBeUndefined();
  const [headerPart, payloadPart, signature] = tokens.id_token.split(".");
  const header = JSON.parse(Buffer.from(headerPart, "base64url").toString());
  expect(header.alg).toBe("RS256");
  const discovery = await context.request.get("http://localhost:14444/.well-known/openid-configuration").then(r => r.json());
  expect(discovery.issuer).toBe("http://localhost:14444/");
  const keys = await context.request.get(discovery.jwks_uri).then(r => r.json());
  const jwk = keys.keys.find((key: { kid: string }) => key.kid === header.kid);
  expect(verify("RSA-SHA256", Buffer.from(headerPart + "." + payloadPart),
    createPublicKey({ key: jwk, format: "jwk" }), Buffer.from(signature, "base64url"))).toBe(true);
  const claims = JSON.parse(Buffer.from(payloadPart, "base64url").toString());
  expect(claims).toMatchObject({ iss: discovery.issuer, sub: "human:fixture-existing-oidc-subject",
    nonce, preferred_username: "alice", email: "alice@example.test", email_verified: false });
  expect([claims.aud].flat()).toContain("gitea-fixture");
  expect(claims.exp).toBeGreaterThan(Date.now() / 1000);
  expect(claims.groups).toEqual(["MixedCase", "gitea-admins"]);
  expect(claims.amr).toEqual(expect.arrayContaining(["pwd", "mfa"]));
  const replay = await context.request.post("http://localhost:14444/oauth2/token", {
    headers: { Authorization: "Basic " + Buffer.from("gitea-fixture:fixture-client-secret").toString("base64") },
    form: { grant_type: "authorization_code", code, redirect_uri: "http://localhost:14446/callback", code_verifier: verifier },
  });
  expect(replay.status()).toBe(400);
  // Hydra remembers its session, but Spring still presents explicit authorization confirmation.
  await page.goto(authorize.toString());
  await expect(page.getByRole("heading", { name: "继续登录 gitea-fixture" })).toBeVisible();
  await page.getByRole("button", { name: "继续至应用", exact: true }).click();
  await expect.poll(() => new URL(page.url()).origin + new URL(page.url()).pathname).toBe("http://localhost:14446/callback");
  expect(new URL(page.url()).searchParams.has("error")).toBe(false);
  const logout = new URL("http://localhost:14444/oauth2/sessions/logout");
  logout.search = new URLSearchParams({ id_token_hint: tokens.id_token, post_logout_redirect_uri: "http://localhost:14446/logged-out" }).toString();
  await page.goto(logout.toString());
  await expect(page.getByRole("heading", { name: "退出统一登录" })).toBeVisible();
  await page.getByRole("button", { name: "确认退出", exact: true }).click();
  await expect.poll(() => new URL(page.url()).origin + new URL(page.url()).pathname).toBe("http://localhost:14446/logged-out");
  await expect.poll(() => logoutTokens.length).toBe(1);
  const [lh, lp, ls] = logoutTokens[0].split(".");
  const logoutHeader = JSON.parse(Buffer.from(lh, "base64url").toString());
  expect(logoutHeader.alg).toBe("RS256");
  const logoutKey = keys.keys.find((key: { kid: string }) => key.kid === logoutHeader.kid);
  expect(verify("RSA-SHA256", Buffer.from(lh + "." + lp), createPublicKey({ key: logoutKey, format: "jwk" }), Buffer.from(ls, "base64url"))).toBe(true);
  const notification = JSON.parse(Buffer.from(lp, "base64url").toString());
  expect(notification.iss).toBe(discovery.issuer);
  expect([notification.aud].flat()).toContain("gitea-fixture");
  expect(claims.sid).toBeTruthy();
  expect(notification.sid).toBe(claims.sid);
  expect(notification.jti).toBeTruthy();
  expect(notification.nonce).toBeUndefined();
  expect(Math.abs(notification.iat - Date.now() / 1000)).toBeLessThan(60);
  expect(notification.events).toEqual({ "http://schemas.openid.net/event/backchannel-logout": {} });
  expect((await context.request.get("https://localhost:18083/api/iam/clients")).status()).toBe(401);

  // Admin UI is an ordinary public client of the same issuer; the API only accepts its bearer token.
  await page.goto("https://localhost:18083/console");
  await expect(page.getByRole("heading", { name: "登录你的账号" })).toBeVisible();
  await page.getByLabel("用户名", { exact: true }).fill("alice");
  await page.getByLabel("密码", { exact: true }).fill("fixture-password");
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await page.getByRole("button", { name: "验证 Passkey", exact: true }).click();
  await expect(page.getByRole("heading", { name: "继续登录 iam-admin-ui" })).toBeVisible();
  await page.getByRole("button", { name: "继续至应用", exact: true }).click();
  await expect(page.getByRole("heading", { name: "OIDC 客户端" })).toBeVisible();
  expect(new URL(page.url()).pathname).toBe("/console");
  await expect(page.getByRole("row", { name: /gitea-fixture/ })).toBeVisible();
  // The public admin client itself is not a manageable (confidential) client.
  await expect(page.getByRole("cell", { name: "iam-admin-ui", exact: true })).toHaveCount(0);

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
  const tokenError = (value: string) => context.request.post("http://localhost:14444/oauth2/token", {
    headers: { Authorization: "Basic " + Buffer.from(`e2e-app:${value}`).toString("base64") },
    form: { grant_type: "authorization_code", code: "invalid-code", redirect_uri: "https://app.example.test/callback" },
  }).then(response => response.json()).then(body => body.error);
  expect(await tokenError(created)).toBe("invalid_client");
  expect(await tokenError(rotated)).toBe("invalid_grant");
  page.once("dialog", dialog => dialog.accept());
  await page.getByRole("row", { name: /e2e-app/ }).getByRole("button", { name: "删除" }).click();
  await expect(page.getByRole("cell", { name: "e2e-app", exact: true })).toHaveCount(0);
});
