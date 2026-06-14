#!/usr/bin/env node
// Atlas render helper: load a Freenet gateway "shell" URL in headless Chromium,
// wait for the sandboxed WASM/SPA frame to populate, and emit JSON describing it
// so the Rust crawler can extract outbound links and a description from a page
// that renders client-side (a static fetch would see only the loader).
//
// Usage:  node render.js <shellUrl> [--shot <pngPath>]
// Output (stdout, one JSON object):
//   { "ok": true, "url": <frameUrl>, "html": <frame outerHTML>, "text": <frame innerText> }
//   { "ok": false, "error": <message> }
//
// The page content is UNTRUSTED. This helper only observes the DOM; it never
// executes page-provided instructions and the caller treats text as data.

const playwright = require('playwright');

const args = process.argv.slice(2);
const url = args[0];
const shotIdx = args.indexOf('--shot');
const shotPath = shotIdx >= 0 ? args[shotIdx + 1] : null;

const NAV_TIMEOUT_MS = 30000;
const POLL_TIMEOUT_MS = 25000; // max time to wait for the WASM frame to populate
const MIN_SETTLE_MS = 6000; // always let content load this long before accepting "stable"
const POLL_STEP_MS = 1000;
const WATCHDOG_MS = 55000; // absolute backstop so we never hang the crawler

// Write the JSON result and exit only once stdout has fully drained. Calling
// process.exit() immediately after a large write truncates output at the OS
// pipe buffer (~64KB), so we wait for the write callback before exiting.
function emit(obj) {
  process.stdout.write(JSON.stringify(obj), () => process.exit(0));
}

// Absolute backstop: if anything wedges, exit with an error rather than hang.
const watchdog = setTimeout(() => {
  emit({ ok: false, error: 'render watchdog timeout' });
}, WATCHDOG_MS);
watchdog.unref();

// Pick the frame most likely to hold the rendered app: prefer one whose URL
// carries the gateway sandbox marker, else the frame with the most text.
async function pickFrame(page) {
  const frames = page.frames();
  const sandbox = frames.filter((f) => f.url().includes('__sandbox'));
  const candidates = sandbox.length ? sandbox : frames;
  let best = null;
  let bestLen = -1;
  for (const f of candidates) {
    let len = 0;
    try {
      len = await f.evaluate(() => (document.body ? document.body.innerText.length : 0));
    } catch (_) {}
    if (len > bestLen) {
      bestLen = len;
      best = f;
    }
  }
  return best || page.mainFrame();
}

(async () => {
  if (!url) {
    emit({ ok: false, error: 'no url' });
    return;
  }
  let browser;
  try {
    browser = await playwright.chromium.launch({ headless: true });
    const page = await browser.newPage({ viewport: { width: 1200, height: 900 } });
    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT_MS }).catch(() => {});

    // Wait for the sandbox app to finish rendering. Many Freenet apps (e.g.
    // Delta) paint their chrome within ~1s but only fetch and render their real
    // content (including outbound links) seconds later, so we cannot stop at the
    // first sign of text. Instead we poll until content STABILIZES: text length
    // and anchor count stop growing for two consecutive polls, after a minimum
    // settle time, bounded by an absolute timeout.
    const deadline = Date.now() + POLL_TIMEOUT_MS;
    const minSettle = Date.now() + MIN_SETTLE_MS;
    let frame = null;
    let prevLen = -1;
    let prevA = -1;
    let stable = 0;
    for (;;) {
      frame = await pickFrame(page);
      let len = 0;
      let a = 0;
      try {
        [len, a] = await frame.evaluate(() => [
          document.body ? document.body.innerText.trim().length : 0,
          document.querySelectorAll('a').length,
        ]);
      } catch (_) {}
      const grew = len !== prevLen || a !== prevA;
      const hasContent = len > 40 || a > 0;
      if (!grew && hasContent && Date.now() > minSettle) {
        if (++stable >= 2) break;
      } else {
        stable = 0;
      }
      prevLen = len;
      prevA = a;
      if (Date.now() > deadline) break;
      await page.waitForTimeout(POLL_STEP_MS);
    }

    frame = await pickFrame(page);
    const html = await frame.evaluate(() => document.documentElement.outerHTML).catch(() => '');
    const text = await frame.evaluate(() => (document.body ? document.body.innerText : '')).catch(() => '');

    if (shotPath) {
      // Screenshot the whole page viewport: the gateway shell is a thin wrapper
      // whose iframe fills the viewport, so this captures the rendered site.
      await page.screenshot({ path: shotPath, fullPage: false }).catch(() => {});
    }

    await browser.close();
    clearTimeout(watchdog);
    emit({ ok: true, url: frame.url(), html, text });
  } catch (e) {
    try { if (browser) await browser.close(); } catch (_) {}
    clearTimeout(watchdog);
    emit({ ok: false, error: String(e && e.message ? e.message : e) });
  }
})();
