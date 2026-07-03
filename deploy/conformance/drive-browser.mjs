// Headless browser driver for the conformance suite's authorization step.
// The suite delivers the authorization response via a JavaScript callback
// page, so a plain HTTP client cannot complete the flow — a real browser is
// needed. Our AS auto-authenticates and 303s straight to the suite callback,
// so simply loading the authorization URL and letting the callback JS run
// completes the flow (no login/consent interaction to script).
//
// Usage: node drive-browser.mjs <authorization-url>
// Requires `playwright` + chromium (installed in the conformance workflow).
import { chromium } from "playwright";

const url = process.argv[2];
if (!url) {
  console.error("usage: drive-browser.mjs <url>");
  process.exit(2);
}

const browser = await chromium.launch({ args: ["--ignore-certificate-errors"] });
try {
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();
  // Load the authorization URL; the AS redirects to the suite callback whose
  // JS posts the response back to the suite.
  await page.goto(url, { waitUntil: "networkidle", timeout: 30000 }).catch(() => {});
  // Give the callback JS a moment to deliver the response.
  await page.waitForTimeout(3000);
  console.log(`[drive-browser] landed on ${page.url()}`);
} finally {
  await browser.close();
}
