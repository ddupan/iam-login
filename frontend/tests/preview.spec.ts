import { test, expect } from "@playwright/test";

test("原生 POST 逐页导航，内联上下文，浏览器缓存静态资源", async ({ page }) => {
  const xhr: string[] = [];
  const posts: string[] = [];
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("request", (req) => {
    if (["fetch", "xhr"].includes(req.resourceType())) xhr.push(req.url());
    if (req.method() === "POST" && req.isNavigationRequest())
      posts.push(req.url());
  });
  await page.goto("/preview");
  await expect(page.getByRole("heading", { name: "从这里开始" })).toBeVisible();
  const scriptUrl = await page.locator("script[src]").getAttribute("src");
  await page.getByRole("button", { name: "这是真实登录吗？" }).click();
  await expect(page.getByText("不是。这里仅演示页面交互")).toBeVisible();
  await page.getByLabel("称呼").fill("预览用户");
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await expect(page).toHaveURL(/\/preview\/verify$/);
  await expect(
    page.getByRole("heading", { name: "你好，预览用户" }),
  ).toBeVisible();
  await page.getByLabel("演示码").fill("000000");
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("演示码不正确");
  await page.getByLabel("演示码").fill("123456");
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await expect(page.getByRole("heading", { name: "体验完成" })).toBeVisible();
  expect(posts).toHaveLength(3);
  expect(xhr).toEqual([]);
  expect(errors).toEqual([]);
  const timing = await page.evaluate(() => ({
    navigation: performance
      .getEntriesByType("navigation")
      .map((e) => e.toJSON()),
    resources: performance.getEntriesByType("resource").map((e) => e.toJSON()),
  }));
  const script = timing.resources.find((r) => r.name.endsWith(scriptUrl!));
  expect(script?.transferSize).toBe(0);
  await test
    .info()
    .attach("navigation-and-cache.json", {
      body: JSON.stringify(timing, null, 2),
      contentType: "application/json",
    });
  expect(
    (
      await page.request.get("/", { headers: { Accept: "application/json" } })
    ).status(),
  ).toBe(401);
  await page.getByRole("button", { name: "重新体验" }).click();
  await expect(page.getByRole("heading", { name: "从这里开始" })).toBeVisible();
});

test("移动端与脚本结束标记作为纯文本显示", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/preview");
  const name = "</script><script>window.__injected=1</script>";
  await page.getByLabel("称呼").fill(name);
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await expect(page.getByRole("heading")).toHaveText(`你好，${name}`);
  expect(
    await page.evaluate(() => Reflect.get(window, "__injected")),
  ).toBeUndefined();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({ path: "test-results/mobile.png", fullPage: true });
});


test("受限网络下首屏和缓存后页面切换计时", async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send("Network.enable");
  await cdp.send("Network.emulateNetworkConditions", {
    offline: false, latency: 60, downloadThroughput: 1_500_000 / 8,
    uploadThroughput: 750_000 / 8,
  });
  await cdp.send("Emulation.setCPUThrottlingRate", { rate: 4 });
  await page.goto("/preview");
  await expect(page.getByRole("heading", { name: "从这里开始" })).toBeVisible();
  const cold = await page.evaluate(() => performance.getEntriesByName("iam-page-ready")[0].startTime);
  await page.getByLabel("称呼").fill("计时体验");
  const start = performance.now();
  await page.getByRole("button", { name: "继续", exact: true }).click();
  await expect(page.getByRole("heading", { name: "你好，计时体验" })).toBeVisible();
  const warm = performance.now() - start;
  const result = { network_latency_ms: 60, download_mbps: 1.5, cpu_slowdown: 4,
    cold_navigation_to_react_commit_ms: Math.round(cold), warm_click_to_visible_ms: Math.round(warm) };
  console.log(JSON.stringify(result));
  await test.info().attach("timing.json", { body: JSON.stringify(result, null, 2), contentType: "application/json" });
});
