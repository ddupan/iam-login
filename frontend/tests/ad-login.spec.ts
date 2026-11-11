import { test, expect } from "@playwright/test";

// Explicit opt-in: never submit synthetic credentials to an arbitrary configured directory.
// The external-domain username below must be rejected before any LDAP bind.
test("AD HTTPS page uses native POST and keeps failed credentials out of the response", async ({ page, context }) => {
  test.skip(!process.env.IAM_AD_URL, "Set IAM_AD_URL to the HTTPS first-factor PoC");
  const url = new URL("/signin", process.env.IAM_AD_URL!);
  expect(url.protocol).toBe("https:");
  const requests: { method: string; type: string; path: string }[] = [];
  page.on("request", request => requests.push({
    method: request.method(), type: request.resourceType(), path: new URL(request.url()).pathname,
  }));
  await page.goto(url.toString());
  await expect(page.getByRole("heading", { name: "登录", exact: true })).toBeVisible();
  await expect(page.locator("form")).toHaveAttribute("method", "post");
  await expect(page.locator("input[name=_csrf]")).toHaveCount(1);
  const session = (await context.cookies()).find(cookie => cookie.name === "SESSION");
  expect(session).toMatchObject({ secure: true, httpOnly: true, sameSite: "Lax" });
  await page.getByLabel("用户名", { exact: true }).fill("ui-check@invalid.example");
  await page.getByRole("button", { name: "继续", exact: true }).click();
  // An unknown name gets the same password step as any account without a passkey.
  await expect(page.getByRole("heading", { name: "输入密码", exact: true })).toBeVisible();
  await page.getByLabel("密码", { exact: true }).fill("synthetic-ui-check");
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("无法验证账号");
  await expect(page.getByLabel("密码", { exact: true })).toHaveValue("");
  expect(await page.content()).not.toContain("synthetic-ui-check");
  expect(requests.filter(request => request.method === "POST" && request.type === "document")).toEqual([
    { method: "POST", type: "document", path: "/signin/identify" },
    { method: "POST", type: "document", path: "/signin/password" },
  ]);
  // The password goes only in the native form post; the one script request is the passkey autofill's challenge.
  expect(requests.filter(request => ["fetch", "xhr"].includes(request.type))
    .every(request => request.path === "/webauthn/authenticate/options")).toBe(true);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth)).toBe(false);
});
