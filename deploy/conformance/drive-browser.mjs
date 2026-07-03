// Headless browser driver for the conformance suite's authorization step.
// The suite delivers the authorization response via a JavaScript callback
// page, so a real browser is needed. Our AS is interactive (P2): the browser
// must log in and approve/deny consent, then land on the suite callback.
//
// The flow is deterministic: /authorize 303s to the login page, the login POST
// 303s back to the SAME /interaction?id= URL now showing the consent page, and
// the consent POST 303s to the client callback. Because login and consent share
// a URL, we key each step on the specific POST response and on the next
// expected element rather than on a URL change — and we click each button
// exactly once (the interaction is one-time-use; a second consent POST 400s).
//
// Usage: node drive-browser.mjs <authorization-url> [approve|deny]
// Requires `playwright` + chromium (installed in the conformance workflow).
import { chromium } from "playwright";

const url = process.argv[2];
const decision = process.argv[3] === "deny" ? "deny" : "approve";
const DEV_USER = process.env.DEV_LOGIN_USER || "dev-user";
if (!url) {
  console.error("usage: drive-browser.mjs <url> [approve|deny]");
  process.exit(2);
}

const browser = await chromium.launch({ args: ["--ignore-certificate-errors"] });
try {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 }).catch(() => {});

  // Step 1 — login (present unless a prior step already authenticated).
  const login = page.locator("#login");
  if ((await login.count()) > 0) {
    const username = page.locator("#username");
    const tag = await username.evaluate((el) => el.tagName).catch(() => null);
    if (tag === "SELECT") await username.selectOption(DEV_USER).catch(() => {});
    else if (tag) await username.fill(DEV_USER).catch(() => {});
    await Promise.all([
      page.waitForResponse((r) => r.url().includes("/interaction/login"), { timeout: 15000 }).catch(() => {}),
      login.click({ timeout: 10000 }).catch(() => {}),
    ]);
  }

  // Step 2 — consent. Wait for the buttons to render (the login POST 303s back
  // to the same /interaction?id= URL, now showing consent), then click once.
  await page.locator("#approve, #deny").first().waitFor({ timeout: 15000 }).catch(() => {});
  const btn = decision === "deny" ? "#deny" : "#approve";
  let clicked = false;
  if ((await page.locator(btn).count()) > 0) {
    await Promise.all([
      page.waitForResponse((r) => r.url().includes("/interaction/consent"), { timeout: 15000 }).catch(() => {}),
      page.locator(btn).click({ timeout: 10000 }).catch(() => {}),
    ]);
    clicked = true;
  }

  // Let the 303 → client callback navigation settle so the suite records it.
  await page.waitForLoadState("load", { timeout: 15000 }).catch(() => {});
  await page.waitForTimeout(2000);
  console.log(`[drive-browser] decision=${decision} landed on ${page.url()}`);
  if (!clicked) {
    // The consent button never rendered — most likely login misconfiguration
    // (DEV_LOGIN_USER not in the AS's DEV_LOGIN_USERS). Fail loudly so it is
    // diagnosable rather than silently leaving the module WAITING.
    console.error(`[drive-browser] no ${btn} button found; the flow did not reach consent`);
    process.exitCode = 1;
  }
} finally {
  await browser.close();
}
