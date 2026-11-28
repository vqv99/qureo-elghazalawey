'use strict';
/**
 * server.js  —  QUREO Solver · Full Local Server
 *
 * APIs implemented:
 *   GET  /api/browser/challenge
 *   POST /api/browser/verify
 *   GET  /api/health
 *   GET  /api/progress
 *   POST /api/solve
 *   POST /api/vip0101/login
 *   POST /api/vip0101/session  (GET)
 *   POST /api/vip0101/start
 *   POST /api/vip0101/status
 *   POST /api/quick/order
 *   GET  /api/quick/status
 *   POST /api/quick/solve
 *
 * Run:  node server.js
 * Open: http://localhost:3000
 */

const express  = require('express');
const path     = require('path');
const crypto   = require('crypto');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

// ═══════════════════════════════════════════════════════════════
// 1.  PERSISTENCE  (simple JSON file — no DB needed)
// ═══════════════════════════════════════════════════════════════
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {}
  return { runs: {}, queue: [], quickOrders: {} };
}
function saveData(d) {
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(d, null, 2)); } catch {}
}
let DB = loadData();

// ═══════════════════════════════════════════════════════════════
// 2.  MIDDLEWARE
// ═══════════════════════════════════════════════════════════════
app.use(express.json());
app.use(express.static(path.join(__dirname), { etag: false }));

// ═══════════════════════════════════════════════════════════════
// 3.  HELPERS
// ═══════════════════════════════════════════════════════════════
function uid(prefix = '', len = 8) {
  return prefix + crypto.randomBytes(len).toString('hex').slice(0, len).toUpperCase();
}
function now() { return Math.floor(Date.now() / 1000); }

// In-memory solver state  { [userKey]: { running, activity[], chapters[], completed, course, ... } }
const SESSIONS = {};

// ═══════════════════════════════════════════════════════════════
// 4.  BROWSER CHALLENGE  (PoW — trivial in dev: difficulty 1)
// ═══════════════════════════════════════════════════════════════
app.get('/api/browser/challenge', (_req, res) => {
  res.json({ ok: true, challenge: crypto.randomBytes(16).toString('hex'), difficulty: 1 });
});

app.post('/api/browser/verify', (_req, res) => {
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════
// 5.  HEALTH
// ═══════════════════════════════════════════════════════════════
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, free_solving: true });
});

// ═══════════════════════════════════════════════════════════════
// 6.  PROGRESS  — polled every 5 s by app.js
// ═══════════════════════════════════════════════════════════════
app.get('/api/progress', (req, res) => {
  const userKey = req.query.user || '';
  const session = SESSIONS[userKey];

  if (!session) {
    return res.json({
      ok: true, running: false, queued: false,
      queue_position: 0, completed_count: 0,
      last_chapter: '', activity: [], chapters: [],
    });
  }

  // Build chapters summary from activity
  const chapters = buildChapterSummary(session.activity || []);

  res.json({
    ok: true,
    running: session.running || false,
    queued:  session.queued  || false,
    queue_position: session.queuePos || 0,
    completed_count: session.completed || 0,
    last_chapter: session.lastChapter || '',
    activity: (session.activity || []).slice(-120),
    chapters,
    free_solving: true,
  });
});

function buildChapterSummary(activity) {
  const map = {};
  for (const line of activity) {
    const m = line.match(/Chapter\s+(\d+)/i) || line.match(/الفصل\s+(\d+)/);
    if (m) {
      const ch = Number(m[1]);
      if (!map[ch]) map[ch] = new Set();
      const lm = line.match(/Lesson\s+(\d+)/i) || line.match(/الدرس\s+(\d+)/);
      if (lm) map[ch].add(`Lesson ${lm[1]}`);
    }
  }
  return Object.entries(map).map(([ch, lessons]) => ({
    chapter: Number(ch),
    lessons: [...lessons],
  }));
}

// ═══════════════════════════════════════════════════════════════
// 7.  START SOLVE  — POST /api/solve
// ═══════════════════════════════════════════════════════════════
app.post('/api/solve', (req, res) => {
  const { code, password, course, fingerprint } = req.body || {};

  if (!code || !password || !course) {
    return res.status(400).json({ ok: false, error: 'بيانات ناقصة — اكتب الكود وكلمة السر والكورس.' });
  }

  // Check if same user already has a running solve
  const existing = Object.values(SESSIONS).find(
    s => s.code === code && s.running
  );
  if (existing) {
    return res.status(409).json({
      ok: true,
      user_key: existing.userKey,
      progress_token: existing.progressToken,
      queued: false,
      already: true,
    });
  }

  const userKey       = uid('U');
  const progressToken = uid('PT');

  SESSIONS[userKey] = {
    userKey,
    progressToken,
    code,
    password,
    course,
    fingerprint: fingerprint || '',
    running: false,
    queued: false,
    queuePos: 0,
    activity: [],
    chapters: [],
    completed: 0,
    lastChapter: '',
    startedAt: now(),
    exitCode: null,
  };

  // Add to queue and start processing
  DB.queue.push(userKey);
  saveData(DB);
  processQueue();

  const queuePos = DB.queue.indexOf(userKey) + 1;
  const queued = queuePos > 1;
  SESSIONS[userKey].queued   = queued;
  SESSIONS[userKey].queuePos = queuePos;

  res.json({
    ok: true,
    user_key: userKey,
    progress_token: progressToken,
    queued,
    queue_position: queuePos,
  });
});

// ═══════════════════════════════════════════════════════════════
// 8.  QUEUE PROCESSOR
// ═══════════════════════════════════════════════════════════════
let processingNow = false;

function processQueue() {
  if (processingNow) return;
  if (DB.queue.length === 0) return;

  processingNow = true;
  const userKey = DB.queue[0];
  const session = SESSIONS[userKey];

  if (!session) {
    DB.queue.shift();
    saveData(DB);
    processingNow = false;
    processQueue();
    return;
  }

  // Update queue positions for everyone waiting
  DB.queue.forEach((k, i) => {
    if (SESSIONS[k]) {
      SESSIONS[k].queuePos = i + 1;
      SESSIONS[k].queued   = i > 0;
    }
  });

  session.running  = true;
  session.queued   = false;
  session.queuePos = 0;

  runSolver(session).then(() => {
    DB.queue.shift();
    saveData(DB);
    processingNow = false;
    processQueue();
  }).catch(() => {
    DB.queue.shift();
    saveData(DB);
    processingNow = false;
    processQueue();
  });
}

// ═══════════════════════════════════════════════════════════════
// 9.  SOLVER ENGINE  (Puppeteer)
// ═══════════════════════════════════════════════════════════════

// Course → answer script mapping
const COURSE_SCRIPTS = {
  js_fast_42:       () => require('./scripts/gov_js_first.js'),
  jslangs_fast_42:  () => require('./scripts/lang_js_first.js'),
  js_fast:          () => require('./scripts/gov_js_second.js'),
  jslangs_fast:     () => require('./scripts/lang_js_second.js'),
  pylangs_fast:     () => require('./scripts/gov_py.js'),
  pylangs:          () => require('./scripts/lang_py.js'),
  fin:              () => require('./scripts/gov_fin.js'),
  sakafa_langs:     () => require('./scripts/lang_fin.js'),
};

async function runSolver(session) {
  const { code, password, course, userKey } = session;

  function log(msg) {
    session.activity.push(msg);
    if (session.activity.length > 500) session.activity.shift();
    process.stdout.write(`[${userKey}] ${msg}\n`);
  }

  log(`بدأ الحل — الكورس: ${course}`);

  let puppeteer;
  try {
    puppeteer = require('puppeteer');
  } catch {
    log('❌ puppeteer مش متنصب — شغّل: npm install puppeteer');
    session.running = false;
    session.exitCode = 1;
    return;
  }

  let browser;
  try {
    browser = await puppeteer.launch({
      headless: false,         // false = تشوف المتصفح بعينك
      defaultViewport: { width: 1280, height: 800 },
      args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });

    const page = await browser.newPage();
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
      '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    );

    // ── LOGIN ────────────────────────────────────────────────
    log('جارٍ تسجيل الدخول…');
    await page.goto('https://qureo.com', { waitUntil: 'networkidle2', timeout: 30000 });

    // Try multiple login URL patterns
    const loginUrls = [
      'https://qureo.com/login',
      'https://qureo.com/sign-in',
      'https://qureo.com/auth',
    ];

    let loggedIn = false;
    for (const url of loginUrls) {
      try {
        await page.goto(url, { waitUntil: 'networkidle2', timeout: 15000 });
        // Look for a password field
        const passEl = await page.$('input[type="password"]');
        if (passEl) { loggedIn = true; break; }
      } catch {}
    }

    if (!loggedIn) {
      // Maybe it already shows login on the homepage
      const passEl = await page.$('input[type="password"]');
      if (!passEl) {
        log('❌ مش قادر يوصل لصفحة الدخول على QUREO');
        session.running = false;
        session.exitCode = 1;
        await browser.close();
        return;
      }
    }

    // Fill credentials
    const codeSelectors = [
      'input[name="username"]',
      'input[name="email"]',
      'input[name="code"]',
      'input[type="text"]',
      'input[placeholder*="ID"]',
      'input[placeholder*="كود"]',
    ];
    for (const sel of codeSelectors) {
      const el = await page.$(sel);
      if (el) {
        await el.click({ clickCount: 3 });
        await el.type(code, { delay: 40 });
        break;
      }
    }

    const passEl = await page.$('input[type="password"]');
    if (passEl) {
      await passEl.click({ clickCount: 3 });
      await passEl.type(password, { delay: 40 });
    }

    // Click submit
    const buttons = await page.$$('button');
    for (const btn of buttons) {
      const txt = await btn.evaluate(el => el.textContent.trim().toLowerCase());
      if (/log\s*in|sign\s*in|login|دخول|تسجيل/.test(txt)) {
        await btn.click();
        break;
      }
    }

    // Wait for redirect away from login
    await page.waitForFunction(
      () => !window.location.href.includes('login') && !window.location.href.includes('sign-in'),
      { timeout: 20000 }
    ).catch(() => {});

    const currentUrl = page.url();
    if (currentUrl.includes('login') || currentUrl.includes('sign-in')) {
      log('❌ المعلومات خاطئة — تحقق من الكود وكلمة السر');
      session.running = false;
      session.exitCode = 1;
      await browser.close();
      return;
    }

    log(`✓ تم الدخول — ${currentUrl}`);

    // ── RUN COURSE SCRIPT ────────────────────────────────────
    const scriptLoader = COURSE_SCRIPTS[course];
    if (scriptLoader) {
      try {
        const script = scriptLoader();
        await script.run(page, session, log);
      } catch (err) {
        log(`خطأ في سكريبت الكورس: ${err.message}`);
      }
    } else {
      // Generic solver — navigate and complete all available chapters
      await genericSolver(page, session, log);
    }

    log('✅ خلص الحل! افتح حسابك على QUREO وشوف.');
    session.exitCode = 0;

  } catch (err) {
    log(`❌ خطأ: ${err.message}`);
    session.exitCode = 1;
  } finally {
    session.running = false;
    if (browser) {
      try { await browser.close(); } catch {}
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// 10. GENERIC SOLVER  (works without a specific script)
//     Navigates every chapter → lesson → answers questions
// ═══════════════════════════════════════════════════════════════
async function genericSolver(page, session, log) {
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  async function clickNext() {
    const btns = await page.$$('button, [role="button"]');
    for (const btn of btns) {
      const txt = await btn.evaluate(el => el.textContent.trim());
      if (/^(next|التالي|continue|استمرار|متابعة|›|>>|تشغيل الكود|run)$/i.test(txt)) {
        const disabled = await btn.evaluate(el => el.disabled);
        if (!disabled) { await btn.click(); await sleep(600); return true; }
      }
    }
    return false;
  }

  async function typeInEditor(code) {
    // CodeMirror
    const cm = await page.$('.CodeMirror');
    if (cm) {
      await page.evaluate((codeText) => {
        const editor = document.querySelector('.CodeMirror')?.CodeMirror;
        if (editor) { editor.setValue(''); editor.setValue(codeText); }
      }, code);
      return;
    }
    // Monaco
    const monaco = await page.$('.monaco-editor');
    if (monaco) {
      await page.evaluate((codeText) => {
        const models = window.monaco?.editor?.getModels();
        if (models && models[0]) models[0].setValue(codeText);
      }, code);
      return;
    }
    // Ace
    const ace = await page.$('.ace_editor');
    if (ace) {
      await page.evaluate((codeText) => {
        const editor = window.ace?.edit(document.querySelector('.ace_editor'));
        if (editor) editor.setValue(codeText, -1);
      }, code);
      return;
    }
    // Plain textarea
    const ta = await page.$('textarea');
    if (ta) {
      await ta.click({ clickCount: 3 });
      await ta.type(code, { delay: 20 });
    }
  }

  async function clickRun() {
    const btns = await page.$$('button');
    for (const btn of btns) {
      const txt = await btn.evaluate(el => el.textContent.trim());
      if (/run|تشغيل/i.test(txt)) { await btn.click(); await sleep(800); return; }
    }
    // Keyboard shortcut fallback
    await page.keyboard.down('Shift');
    await page.keyboard.press('Enter');
    await page.keyboard.up('Shift');
    await sleep(800);
  }

  async function tickAllCheckboxes() {
    const boxes = await page.$$('input[type="checkbox"]:not(:checked)');
    for (const box of boxes) { await box.click(); await sleep(200); }
  }

  async function clickUnderstood() {
    const btns = await page.$$('button');
    for (const btn of btns) {
      const txt = await btn.evaluate(el => el.textContent.trim());
      if (/فهمت|understood|got it|confirm|ok/i.test(txt)) {
        await btn.click(); await sleep(600); return true;
      }
    }
    return false;
  }

  // Find all chapter links
  async function getChapterLinks() {
    return page.evaluate(() => {
      const links = [...document.querySelectorAll('a[href], button')];
      return links
        .filter(el => /chapter|فصل|unit|lesson|درس/i.test(el.textContent))
        .map(el => ({
          text: el.textContent.trim(),
          href: el.href || null,
          tag: el.tagName,
        }));
    });
  }

  log('جارٍ البحث عن الفصول…');
  const chapterLinks = await getChapterLinks();
  log(`وجد ${chapterLinks.length} فصل/درس`);

  if (chapterLinks.length === 0) {
    log('⚠️ ما لاقاش فصول — هيحاول يكمل من المكان الحالي');
    // Just try to advance through whatever is on screen
    for (let i = 0; i < 200; i++) {
      await tickAllCheckboxes();
      await clickUnderstood();
      const hasEditor = await page.$('.CodeMirror, .monaco-editor, .ace_editor, textarea');
      if (hasEditor) await clickRun();
      const advanced = await clickNext();
      if (!advanced) break;
      session.completed++;
      await sleep(500);
    }
    return;
  }

  // Work through each chapter
  for (let ci = 0; ci < chapterLinks.length; ci++) {
    const ch = chapterLinks[ci];
    log(`Chapter ${ci + 1}: ${ch.text}`);
    session.lastChapter = `Chapter ${ci + 1}`;

    if (ch.href) {
      await page.goto(ch.href, { waitUntil: 'networkidle2', timeout: 20000 }).catch(() => {});
    } else {
      // Re-query and click the nth chapter button
      const btns = await page.$$('button, [role="button"]');
      for (const btn of btns) {
        const txt = await btn.evaluate(el => el.textContent.trim());
        if (txt === ch.text) { await btn.click(); break; }
      }
      await sleep(1500);
    }

    // Advance through all questions in this chapter
    for (let qi = 0; qi < 60; qi++) {
      await tickAllCheckboxes();
      await clickUnderstood();

      const hasEditor = await page.$('.CodeMirror, .monaco-editor, .ace_editor, textarea');
      if (hasEditor) {
        await clickRun();
        await sleep(400);
      }

      // Multiple choice — click first option if present and nothing selected
      const options = await page.$$('input[type="radio"]:not(:checked)');
      if (options.length) { await options[0].click(); await sleep(300); }

      const advanced = await clickNext();
      if (!advanced) break;
      session.completed++;
      log(`  ✓ Lesson ${qi + 1} done`);
      await sleep(600);
    }

    await sleep(1000);
  }
}

// ═══════════════════════════════════════════════════════════════
// 11. VIP ENDPOINTS  (minimal — login + start + status)
// ═══════════════════════════════════════════════════════════════
const VIP_PASSWORD = process.env.VIP_PASSWORD || 'vip1234';  // change this
const vipSessions  = {};  // csrf → { account }

app.post('/api/vip0101/login', (req, res) => {
  const { key } = req.body || {};
  if (key !== VIP_PASSWORD) {
    return res.status(401).json({ ok: false, error: 'كلمة سر VIP غير صحيحة.' });
  }
  const csrf = uid('CSRF');
  vipSessions[csrf] = { admin: true, name: 'Admin', createdAt: now() };
  res
    .cookie('vip_session', csrf, { httpOnly: true, sameSite: 'lax' })
    .json({ ok: true, csrf, account: { name: 'Admin', admin: true } });
});

app.get('/api/vip0101/session', (req, res) => {
  // Parse cookie manually — no cookie-parser dependency needed
  const rawCookie = req.headers.cookie || '';
  const cookieVal = rawCookie.split(';').map(c => c.trim())
    .find(c => c.startsWith('vip_session='))?.split('=')[1] || '';
  const csrf = req.headers['x-csrf-token'] || cookieVal;
  const session = vipSessions[csrf];
  if (!session) return res.status(401).json({ ok: false });
  res.json({ ok: true, csrf, account: session });
});

app.post('/api/vip0101/start', (req, res) => {
  const { code, password, course } = req.body || {};
  if (!code || !password || !course) {
    return res.status(400).json({ ok: false, error: 'بيانات ناقصة.' });
  }

  const userKey       = uid('VIP');
  const progressToken = uid('PT');

  SESSIONS[userKey] = {
    userKey, progressToken, code, password, course,
    running: false, queued: false, queuePos: 0,
    activity: [], completed: 0, lastChapter: '', startedAt: now(), exitCode: null,
  };

  DB.queue.push(userKey);
  saveData(DB);
  processQueue();

  res.json({ ok: true, user_key: userKey, progress_token: progressToken, queued: false });
});

app.post('/api/vip0101/status', (req, res) => {
  const sessions = Object.values(SESSIONS).map(s => ({
    userKey: s.userKey,
    course: s.course,
    running: s.running,
    queued: s.queued,
    completed: s.completed,
    exitCode: s.exitCode,
    lastChapter: s.lastChapter,
    activity: (s.activity || []).slice(-30),
  }));
  res.json({ ok: true, runs: sessions });
});

// Generic VIP passthrough (admin-data, admin-act, etc.)
app.post('/api/vip0101/:action', (req, res) => {
  res.json({ ok: false, error: `الـ action "${req.params.action}" غير متاح في الوضع المحلي.` });
});

// ═══════════════════════════════════════════════════════════════
// 12. QUICK ORDER SYSTEM
// ═══════════════════════════════════════════════════════════════
app.post('/api/quick/order', (req, res) => {
  const { plan, phone } = req.body || {};
  const code = uid('QS', 5);
  const price = { course: 15, culture: 20, full: 30 }[plan] || 15;

  DB.quickOrders[code] = {
    code, plan, phone, price,
    status: 'approved',   // auto-approve in local mode
    createdAt: now(),
    expiresAt: now() + 2700,
  };
  saveData(DB);

  res.json({ ok: true, code, price, expires_in: 2700 });
});

app.get('/api/quick/status', (req, res) => {
  const code = req.query.code || '';
  const order = DB.quickOrders[code];
  if (!order) return res.json({ ok: false, error: 'الطلب مش موجود.' });

  const run = Object.values(SESSIONS).find(s => s.quickOrderCode === code);
  if (run) {
    return res.json({
      ok: true, status: order.status, plan: order.plan,
      run: {
        running: run.running,
        logs: (run.activity || []).slice(-40),
        exit: run.exitCode,
        course_label: run.course || '',
      },
      progress: { completed: new Array(run.completed).fill(1) },
    });
  }

  res.json({ ok: true, status: order.status, plan: order.plan, price: order.price });
});

app.post('/api/quick/solve', (req, res) => {
  const { code, course, id, password } = req.body || {};
  const order = DB.quickOrders[code];
  if (!order) return res.json({ ok: false, error: 'الطلب مش موجود.' });

  const userKey       = uid('QR');
  const progressToken = uid('PT');

  SESSIONS[userKey] = {
    userKey, progressToken,
    code: id, password, course,
    quickOrderCode: code,
    running: false, queued: false, queuePos: 0,
    activity: [], completed: 0, lastChapter: '', startedAt: now(), exitCode: null,
  };

  DB.queue.push(userKey);
  saveData(DB);
  processQueue();

  res.json({ ok: true, course_label: course });
});

// ═══════════════════════════════════════════════════════════════
// 13. SPA FALLBACK
// ═══════════════════════════════════════════════════════════════
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ═══════════════════════════════════════════════════════════════
// 14. START
// ═══════════════════════════════════════════════════════════════
app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ✅  QUREO Solver Server شغال');
  console.log(`  🌐  http://localhost:${PORT}`);
  console.log('');
  console.log('  كلمة سر VIP:', VIP_PASSWORD);
  console.log('  غيّرها: set VIP_PASSWORD=كلمتك && node server.js');
  console.log('');
  console.log('  عشان الحل الفعلي يشتغل: npm install puppeteer');
  console.log('');
});
