// Run with: npm ci --prefix tests --ignore-scripts
// Then: npx --prefix tests playwright install chromium && node tests/ui-security.cjs
// Uses a new isolated browser profile and mocked HTTP; no production data or provider calls.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.CHROME_PATH ? {executablePath: process.env.CHROME_PATH} : {}) });
  try {
    const page = await browser.newPage({locale:'en-US',timezoneId:'UTC'});
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const assets = path.resolve(__dirname, '../internal/server/assets');
    const attack = '<img src=x onerror="window.pwned=1"><svg onload="window.pwned=1"></svg>';
    await page.route('**/*', route => {
      const url = new URL(route.request().url());
      if (url.origin !== 'http://jvmdiag.test') return route.abort();
      if (url.pathname === '/') return route.fulfill({contentType: 'text/html', body: fs.readFileSync(path.join(assets, 'app.html'), 'utf8')});
      if (url.pathname === '/js/marked.umd.js') return route.fulfill({contentType: 'application/javascript', body: fs.readFileSync(path.join(assets, 'js/marked.umd.js'), 'utf8')});
      if (url.pathname.startsWith('/api/') && !route.request().headers()['authorization']) return route.fulfill({status: 401, json: {error: 'Access token required'}});
      if (url.pathname === '/api/heap/upload') return route.fulfill({json:{analysisId:'quality-job'}});
      if (url.pathname === '/api/analysis/quality-job/status') return route.fulfill({json:{status:'COMPLETED',fileName:'limited.hprof',engineUsed:'native-hprof',staticReport:'Analysis status: limited',assessment:{status:'limited',scope:'payload only',warnings:[attack],limitations:['retained size unavailable']}}});
      if (url.pathname === '/api/history') return route.fulfill({json: [{id: "');window.pwned=1;//", fileName: attack, analysisType: attack, engineUsed: attack, savedAt: '2026-01-01T00:00:00Z'}]});
      if (url.pathname === '/api/settings') return route.fulfill({json: {configured: false, canManageGlobal: false}});
      if (url.pathname === '/api/mcp/status') return route.fulfill({json: {active: true, fileName: attack, engineUsed: attack, parseError: attack, sessionId: 'safe', parsed: true}});
      if (url.pathname === '/api/mcp/chat') return route.fulfill({json: {turnCount: 0}});
      if (url.pathname === '/css/app.css') return route.fulfill({contentType: 'text/css', body: fs.readFileSync(path.join(assets, 'css/app.css'), 'utf8')});
      return route.fulfill({json: {}});
    });
    await page.goto('http://jvmdiag.test/?workspace=' + encodeURIComponent(attack));
    await page.waitForFunction(() => document.getElementById('history-container').textContent.includes('Access token required'));
    await page.locator('#access-token').fill('browser-test-token');
    await page.getByRole('button', {name: 'Connect', exact: true}).click();
    await page.waitForSelector('.history-table');
    assert.equal(await page.locator('#access-token').inputValue(), '');
    assert.equal(await page.evaluate(() => localStorage.getItem('jvmdiag_access_token')), null);
    assert.equal(await page.locator('#history-container img, #history-container svg').count(), 0);
    assert.ok((await page.locator('#history-container').innerText()).includes(attack));
    // A hostile persisted ID must be encoded as a URL component and never interpolated into JS.
    const historyLink = page.locator('#history-container a');
    assert.equal(await historyLink.getAttribute('onclick'), null);
    assert.ok((await historyLink.getAttribute('href')).includes('%3B'));
    await page.evaluate(() => navTo('/mcp'));
    await page.waitForFunction(() => document.getElementById('mcp-session-info').textContent.includes('Active Session:'));
    assert.equal(await page.locator('#mcp-session-info img, #mcp-session-info svg').count(), 0);
    const result = await page.evaluate(() => {
      const target = document.createElement('div');
      document.body.appendChild(target);
      renderMarkdown(target, `# Safe heading\n\n**bold**\n\n[unsafe](javascript:alert(1))\n\n<a href="jav&#x61;script:alert(1)" onclick="window.pwned=1">bad</a>\n\n<img src=x onerror="window.pwned=1">\n\n<svg onload="window.pwned=1"><a href="javascript:alert(1)">bad</a></svg>\n\n<iframe srcdoc="<script>window.pwned=1</script>"></iframe>\n\n<form><input name=replaceChildren></form>\n\n[good](https://example.com)\n\n<table><tr><td style="background:url(x)" onmouseover="window.pwned=1">cell</td></tr></table>`);
      return {
        tags: [...target.querySelectorAll('*')].map(n => n.tagName),
        attrs: [...target.querySelectorAll('*')].flatMap(n => [...n.attributes].map(a => a.name + '=' + a.value)),
        heading: target.querySelector('h1')?.textContent,
        bold: target.querySelector('strong')?.textContent,
        good: target.querySelector('a[href="https://example.com/"]')?.getAttribute('rel'),
      };
    });
    assert.equal(result.heading, 'Safe heading');
    assert.equal(result.bold, 'bold');
    assert.equal(result.good, 'noopener noreferrer');
    assert.ok(!result.tags.some(tag => ['IMG','SVG','IFRAME','SCRIPT','FORM','INPUT'].includes(tag)));
    assert.ok(!result.attrs.some(attr => /^on|^style=|javascript:/i.test(attr)));
    assert.equal(await page.evaluate(() => window.pwned), undefined);
    // Fallback without the Markdown library must remain safe and usable.
    assert.equal(await page.evaluate(() => {
      const previous = window.marked; window.marked = undefined;
      const target = document.createElement('div'); renderMarkdown(target, '<img src=x onerror=alert(1)>');
      window.marked = previous;
      return target.childElementCount;
    }), 0);
    await page.evaluate(() => navTo('/heap'));
    await page.evaluate(() => startUploadJob('/api/heap/upload', new FormData()));
    await page.waitForFunction(() => document.getElementById('job-quality-badge').textContent.includes('limited'));
    assert.ok((await page.locator('#step-static').innerText()).includes('limitations'));
    assert.ok((await page.locator('#step-ai').innerText()).includes('limited'));
    assert.equal(await page.locator('#job-quality-badge img').count(), 0);
    assert.deepEqual(errors, []);
    console.log('PASS: stored filenames, IDs, workspace labels, session errors, Markdown HTML/URLs and offline fallback');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
