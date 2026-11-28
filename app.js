// Frontend only. Language Schools = 100% English. Government = 100% Arabic.
// Wrong-course ("undefined 'id'") detection is done HERE only — solvers untouched.
// Same-origin only: API overrides and admin keys in URLs/storage are deliberately unsupported.
const API_BASE = '';
const BROWSER_HEADERS = { 'X-Qureo-Browser': '1' };
const MAX_BULK_CONCURRENCY = 2;

// Compatible with browsers that do not support native abort timeouts.
async function fetchWithTimeout(url, options = {}, timeoutMs = 20000) {
  if (typeof AbortController === 'undefined') return fetch(url, options);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

const volatileStorage = new Map();
function createSafeStorage(area) {
  const prefix = area + ':';
  return {
    getItem(key) {
      try {
        const value = window[area].getItem(key);
        return value === null ? (volatileStorage.get(prefix + key) ?? null) : value;
      } catch { return volatileStorage.get(prefix + key) ?? null; }
    },
    setItem(key, value) {
      volatileStorage.set(prefix + key, String(value));
      try { window[area].setItem(key, String(value)); } catch {}
    },
    removeItem(key) {
      volatileStorage.delete(prefix + key);
      try { window[area].removeItem(key); } catch {}
    },
  };
}
const storageLocal = createSafeStorage('localStorage');
const storageSession = createSafeStorage('sessionStorage');
storageLocal.removeItem('qureoAdmin');
storageLocal.removeItem('qureoApiBase');
storageSession.removeItem('vip0101Key');
storageSession.removeItem('vip0101AccountId');

function proofHasLeadingZeroBits(buffer, bits) {
  const bytes = new Uint8Array(buffer);
  const wholeBytes = Math.floor(bits / 8);
  const remainingBits = bits % 8;
  for (let index = 0; index < wholeBytes; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  return remainingBits === 0 || bytes[wholeBytes] >> (8 - remainingBits) === 0;
}

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const SHA256_ENCODER = new TextEncoder();

function sha256Bytes(message) {
  const input = SHA256_ENCODER.encode(message);
  const block = new Uint8Array(64);
  block.set(input);
  block[input.length] = 0x80;
  const view = new DataView(block.buffer);
  view.setUint32(60, input.length * 8, false);
  const words = new Uint32Array(64);
  for (let index = 0; index < 16; index += 1) words[index] = view.getUint32(index * 4, false);
  for (let index = 16; index < 64; index += 1) {
    const x = words[index - 15];
    const y = words[index - 2];
    const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
    const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
    words[index] = (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
  }
  let a = 0x6a09e667; let b = 0xbb67ae85; let c = 0x3c6ef372; let d = 0xa54ff53a;
  let e = 0x510e527f; let f = 0x9b05688c; let g = 0x1f83d9ab; let h = 0x5be0cd19;
  for (let index = 0; index < 64; index += 1) {
    const s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
    const choice = (e & f) ^ (~e & g);
    const temp1 = (h + s1 + choice + SHA256_K[index] + words[index]) >>> 0;
    const s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
    const majority = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (s0 + majority) >>> 0;
    h = g; g = f; f = e; e = (d + temp1) >>> 0;
    d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
  }
  const output = new Uint8Array(32);
  const outputView = new DataView(output.buffer);
  const state = [a, b, c, d, e, f, g, h].map((value, index) => (value + [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19][index]) >>> 0);
  state.forEach((value, index) => outputView.setUint32(index * 4, value, false));
  return output;
}

async function getBrowserProof(scope) {
  let data = null;
  let lastError = null;
  for (let attempt = 0; attempt < 3 && !data; attempt += 1) {
    try {
      const burst = `${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const response = await fetchWithTimeout(`${API_BASE}/api/browser/challenge?scope=${encodeURIComponent(scope)}&_=${burst}`, {
        headers: BROWSER_HEADERS,
        cache: 'no-store',
        credentials: 'same-origin',
      });
      const text = await response.text();
      let candidate = {};
      try { candidate = text ? JSON.parse(text) : {}; } catch { candidate = {}; }
      if (!response.ok || !candidate.ok) {
        const error = new Error(candidate.error || 'تعذر التحقق من المتصفح. حاول مرة أخرى.');
        error.code = response.status === 429 ? 'RATE_LIMITED' : 'BROWSER_CHECK';
        throw error;
      }
      if (!/^[a-f0-9]{32}$/.test(String(candidate.challenge || ''))) throw new Error('استجابة التحقق غير صالحة. حاول مرة أخرى.');
      data = candidate;
    } catch (error) {
      lastError = error;
      if (error.code === 'RATE_LIMITED') throw error;
      if (attempt < 2) await new Promise((resolve) => setTimeout(resolve, 350 * (attempt + 1)));
    }
  }
  if (!data) throw lastError || new Error('تعذر التحقق من المتصفح. حاول مرة أخرى.');
  const challenge = String(data.challenge || '');
  const difficulty = Number(data.difficulty || 14);
  const started = Date.now();
  for (let nonce = 0; nonce <= 0xffffffff; nonce += 1) {
    const digest = sha256Bytes(`${challenge}:${nonce}`);
    if (proofHasLeadingZeroBits(digest, difficulty)) return { challenge, nonce: String(nonce) };
    if ((nonce & 2047) === 2047) {
      if (Date.now() - started > 110000) throw new Error('انتهت مهلة التحقق من المتصفح. حاول مرة أخرى.');
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
  throw new Error('تعذر إكمال التحقق من المتصفح.');
}

const VIP_MODE = /^\/vip0101\/?$/.test(location.pathname);
const VERIFY_MODE = Boolean(document.querySelector('#browser-verify'));
if (VERIFY_MODE) {
  initBrowserVerification();
} else if (VIP_MODE) {
  initVip0101();
} else {
  let currentUser = storageLocal.getItem('qureoUserKey') || '';
  let progressToken = storageLocal.getItem('qureoProgressToken') || '';
  let deviceFp = storageLocal.getItem('qureoFp');
  if (!deviceFp) {
    deviceFp = 'fp-' + Math.random().toString(36).slice(2) + '-' + Date.now().toString(36);
    storageLocal.setItem('qureoFp', deviceFp);
  }

  const form = document.querySelector('#solve-form');
  const button = document.querySelector('#start-button');
  const statusBox = document.querySelector('#status');
  const chaptersBox = document.querySelector('#chapters');
  const activityBox = document.querySelector('#activity');
  const activityCount = document.querySelector('#activity-count');
  const runningBadge = document.querySelector('#running-badge');
  const courseCards = document.querySelector('#course-cards');
  const stepIndicator = document.querySelector('#step-indicator');
  const btnNext = document.querySelector('#btn-next');
  const btnBack = document.querySelector('#btn-back');
  const joinModal = document.querySelector('#join-modal');
  const categoryModal = document.querySelector('#category-modal');
  const yearModal = document.querySelector('#year-modal');
  const mismatchModal = document.querySelector('#mismatch-modal');
  const credentialsModal = document.querySelector('#credentials-modal');
  const credentialCode = document.querySelector('#credential-code');
  const credentialPassword = document.querySelector('#credential-password');
  const credentialError = document.querySelector('#credential-error');
  const credentialRetry = document.querySelector('#credential-retry');
  const selectionPill = document.querySelector('#selection-pill');
  const confirmNote = document.querySelector('#confirm-note');
  const joinedButton = document.querySelector('#joined-button');

  let refreshing = false;
  let progressFailures = 0;
  let lastQueued = false;
  let activitySignature = '';
  let chaptersSignature = '';
  let selectedTrack = storageSession.getItem('qureoTrack') || '';
  let selectedYear = storageSession.getItem('qureoYear') || '';
  let selectedCourse = '';
  let step = 1;
  let solveJustStarted = false;
  let uiLanguage = 'ar';
  let mismatchHandled = '';
  let lastActivity = [];
  let lastChapters = [];
  let solveActivityBaseline = '[]';
  let credentialsTrack = '';
  let startingSolve = false;
  let solveInProgress = false;
  let rateLimitedUntil = 0;

  const COURSES_BY_TRACK = {
    government: {
      one: [
        { key: 'js_fast_42', label: 'JavaScript', labelAr: 'جافاسكربت', desc: '42 chapters · Government schools', descAr: '42 فصل · مدارس حكومي' },
      ],
      two: [
        { key: 'js_fast', label: 'JavaScript', labelAr: 'جافاسكربت', desc: '54 chapters · Government schools', descAr: '54 فصل · مدارس حكومي' },
        { key: 'pylangs_fast', label: 'Python', labelAr: 'بايثون', desc: 'Complete course · Government schools', descAr: 'الكورس كامل · مدارس حكومي' },
        { key: 'fin', label: 'Financial Literacy', labelAr: 'ثقافة مالية', desc: 'Complete course · Government schools', descAr: 'الكورس كامل · مدارس حكومي' },
      ],
    },
    language: {
      one: [
        { key: 'jslangs_fast_42', label: 'JavaScript — Language Schools', desc: '42 chapters · First year' },
      ],
      two: [
        { key: 'jslangs_fast', label: 'JavaScript — Language Schools', desc: '54 chapters · Second year' },
        { key: 'pylangs', label: 'Python — Language Schools', desc: 'Complete course · Second year' },
        { key: 'sakafa_langs', label: 'Financial Literacy — Language Schools', desc: 'English course · 134 items' },
      ],
    },
  };

  const TEXT = {
    brandName: ['QUREO', 'حل كيريو'],
    brandSub: ['SOLVER', 'QUREO'],
    brandFooter: ['QUREO SOLVER', 'حل كيريو'],
    joinKicker: ['ONE QUICK STEP', 'خطوة واحدة سريعة'],
    joinTitle: ['Stay in the loop', 'تابع كل جديد'],
    joinBody: ['Get solver updates and new course releases on Telegram, then continue to the platform.', 'تابع تحديثات الحل والكورسات الجديدة على تيليجرام، وبعدها كمل للمنصة.'],
    joinOpen: ['Open Telegram', 'فتح تيليجرام'],
    joinedButton: ['I’ve joined — continue', 'انضمت — متابعة'],
    categoryKicker: ['MOST IMPORTANT STEP', 'أهم خطوة — ظبطها صح'],
    categoryTitle: ['Is your QUREO account in Arabic or English?', 'حسابك على كيريو بالعربي ولا بالإنجليزي؟'],
    categoryIntro: ['Pick Government for an Arabic portal, Language Schools for an English one. A wrong pick stops the solve instantly.', 'دي أهم خطوة! لو حسابك بالعربي اختار «حكومي»، ولو بالإنجليزي اختار «لغات». الاختيار الغلط بيخلي الحل يقف من أوله.'],
    govCard: ['Government', 'حكومي'],
    govCardDesc: ['Arabic QUREO portal · Year 1 & Year 2', 'حساب كيريو بالعربي — أولى وتانية بكالوريا'],
    langCard: ['Language Schools', 'لغات'],
    langCardDesc: ['English QUREO portal · JavaScript, Python & Financial Literacy', 'حساب كيريو بالإنجليزي — جافاسكربت وبايثون وثقافة مالية'],
    yearTitle: ['Choose your year', 'اختار سنتك'],
    yearBack: ['Back to school type', 'رجوع لنوع المدرسة'],
    yearKickerGov: ['GOVERNMENT SCHOOLS', 'مدارس حكومي'],
    yearKickerLang: ['LANGUAGE SCHOOLS', 'مدارس لغات'],
    yearBodyGov: ['Your year sets the right government course and chapter range.', 'سنتك بتحدد الكورس الحكومي وعدد الفصول الصحيح.'],
    yearBodyLang: ['Your year sets the right language-schools course and chapter range.', 'سنتك بتحدد كورس اللغات وعدد الفصول الصحيح.'],
    yearOne: ['First Year', 'أولى بكالوريا'],
    yearTwo: ['Second Year', 'تانية بكالوريا'],
    yearOneGovDesc: ['JavaScript · 42 chapters · Government', 'جافاسكربت · 42 فصل'],
    yearTwoGovDesc: ['JavaScript (54) · Python · Financial Literacy', 'جافاسكربت (54 فصل) · بايثون · ثقافة مالية'],
    yearOneLangDesc: ['JavaScript · 42 chapters · Language Schools', 'JavaScript · 42 فصل · لغات'],
    yearTwoLangDesc: ['JavaScript (54) · Python · Financial · Language Schools', 'JavaScript (54) وPython وFinancial · لغات'],
    trackGov: ['Government', 'حكومي'],
    trackLang: ['Language Schools', 'لغات'],
    yearShortOne: ['Year 1', 'أولى'],
    yearShortTwo: ['Year 2', 'تانية'],
    pickTrack: ['Pick school type & year ✎', 'اختار نوع مدرستك وسنتك ✎'],
    confirmNote: ['Final check — you are solving: {course} · {track} · {year}', 'تأكيد أخير — هتحل: {course} · {track} · {year}'],
    mismatchKicker: ['WRONG COURSE', 'اختيار غير صحيح'],
    mismatchTitleGov: ['You’re Language Schools but picked Government 😅', 'انت لغات لكن مختار حكومي 😅'],
    mismatchTitleLang: ['You’re Government but picked Language Schools 😅', 'انت حكومي لكن مختار لغات 😅'],
    mismatchBodyGov: ['Your QUREO account is on the English portal (Language Schools), but you picked Government. Hit "Edit selection" and choose Language Schools to start the right solve.', 'حسابك على كيريو بالإنجليزي (لغات)، بس انت اخترت «حكومي». دوس «تعديل الاختيار» واختار «لغات» عشان يبدأ الحل الصح.'],
    mismatchBodyLang: ['Your QUREO account is on the Arabic portal (Government), but you picked Language Schools. Hit "Edit selection" and choose Government to start the right solve.', 'حسابك على كيريو بالعربي (حكومي)، بس انت اخترت «لغات». دوس «تعديل الاختيار» واختار «حكومي» عشان يبدأ الحل الصح.'],
    mismatchRetry: ['Edit selection', 'تعديل الاختيار'],
    mismatchClose: ['Dismiss', 'إغلاق'],
    mismatchStatusGov: ['You’re Language Schools but picked Government — hit Edit selection and choose Language Schools.', 'انت لغات لكن مختار حكومي — دوس «تعديل الاختيار» واختار «لغات».'],
    mismatchStatusLang: ['You’re Government but picked Language Schools — hit Edit selection and choose Government.', 'انت حكومي لكن مختار لغات — دوس «تعديل الاختيار» واختار «حكومي».'],
    heroKicker: ['ONE PLATFORM. EVERY COURSE.', 'منصة واحدة. كل الكورسات.'],
    heroLine1: ['Choose it. Solve it.', 'اختارها. حلها.'],
    heroLine2: ['Move forward.', 'وتقدّم للأمام.'],
    heroBody: ['Fast, accurate course completion with a private live feed for every session. No clutter—just the courses that belong to your year.', 'حل سريع ودقيق للكورسات مع نشاط مباشر خاص بكل جلسة. من غير زحمة—بس الكورسات المناسبة لسنتك.'],
    tagActive: ['30 active solvers', '30 حل نشط'],
    tagQueue: ['Smart queue', 'طابور ذكي'],
    tagProgress: ['Live progress', 'تقدم مباشر'],
    startTitle: ['Start a new solve', 'ابدأ حل جديد'],
    startSubtitle: ['Four quick steps. We handle the rest.', 'أربع خطوات سريعة. والباقي علينا.'],
    courseLabel: ['Choose your course', 'اختار الكورس'],
    courseDesc: ['Only courses for your year are shown. Tap the pill above to change school type or year.', 'هتظهر بس الكورسات المناسبة لسنتك. دوس على البطاقة اللي فوق لو عايز تغيّر نوع المدرسة أو السنة.'],
    phoneLabel: ['Phone number', 'رقم الموبايل'],
    phonePlaceholder: ['05xxxxxxxx', '05xxxxxxxx'],
    phoneHint: ['Used only if we need to contact you about your session.', 'هنستخدمه بس لو احتجنا نتواصل معاك بخصوص جلستك.'],
    codeLabel: ['Student ID', 'كود الطالب'],
    codePlaceholder: ['Enter your QUREO student ID', 'اكتب كود الطالب بتاع كيريو'],
    codeHint: ['The student ID assigned to your QUREO account.', 'كود الطالب المخصص لحسابك على كيريو.'],
    passwordLabel: ['Password', 'كلمة السر'],
    passwordPlaceholder: ['Enter your QUREO password', 'اكتب كلمة سر كيريو'],
    passwordHint: ['Your credentials are used only to complete your selected course.', 'بياناتك بتتستخدم بس لإكمال الكورس اللي اخترته.'],
    backButton: ['Back', 'رجوع'],
    nextButton: ['Next', 'التالي'],
    startButton: ['Start solving', 'ابدأ الحل'],
    readyStatus: ['Ready when you are.', 'جاهزين لما تكون جاهز.'],
    privacyNote: ['One active solve per device', 'حل واحد نشط لكل جهاز'],
    progressTitle: ['Live progress', 'التقدم المباشر'],
    progressSubtitle: ['Updates from your current session only.', 'تحديثات من جلستك الحالية بس.'],
    idle: ['Idle', 'متوقف'],
    completedItems: ['Completed items', 'عناصر مكتملة'],
    latestChapter: ['Latest chapter', 'آخر فصل'],
    solverStatus: ['Solver status', 'حالة الحل'],
    activityTitle: ['Activity feed', 'النشاط المباشر'],
    chaptersTitle: ['Chapters', 'الفصول'],
    sessionOnly: ['Your session only', 'جلستك بس'],
    emptyActivity: ['Your session activity will appear here.', 'نشاط جلستك هيظهر هنا.'],
    emptyChapters: ['No progress for this account yet.', 'لسه مفيش تقدم للحساب ده.'],
    footerTagline: ['Less waiting. More learning.', 'انتظار أقل. تعلم أكتر.'],
    stepOf: ['Step {step} of 4', 'الخطوة {step} من 4'],
    courseSelected: ['{course} selected. Click Next to continue.', 'تم اختيار {course}. دوس التالي عشان تكمل.'],
    chooseCourse: ['Choose a course to continue.', 'اختار كورس عشان تكمل.'],
    phoneRequired: ['Enter your phone number first.', 'اكتب رقم موبايلك الأول.'],
    codeRequired: ['Enter your student ID first.', 'اكتب كود الطالب الأول.'],
    passwordRequired: ['Enter your password first.', 'اكتب كلمة السر الأول.'],
    goBackCourse: ['Go back and choose a course first.', 'ارجع واختار الكورس الأول.'],
    joinedSuccess: ['You’re all set. Continue below.', 'تم التفعيل. كمل من تحت.'],
    starting: ['Starting your solve…', 'جارٍ بدء الحل…'],
    started: ['Your solve has started. Watch the live activity below.', 'بدأ الحل. تابع النشاط المباشر تحت.'],
    queueFirst: ['You are number 1 in queue — your solve starts as soon as any request finishes.', 'انت دورك رقم: 1 — هيبدأ الحل أول ما أي طلب يخلص.'],
    queueLater: ['You are number {position} in queue — your solve starts after {remaining} requests.', 'انت دورك رقم: {position} — هيبدأ الحل بعد {remaining} طلبات قبلك.'],
    queueStatus: ['Queue #{position}', 'دورك رقم {position}'],
    solvingNow: ['Solving now', 'يعمل الآن'],
    invalidCredentials: ['Invalid login credentials.', 'بيانات الدخول غير صحيحة.'],
    credentialsTitle: ['Your details are incorrect. Enter the correct ID:', 'معلوماتك غلط! اكتب الكود صح:'],
    credentialCode: ['ID', 'الكود'],
    credentialPassword: ['Password', 'الباسورد'],
    credentialsTrack: ['Are you sure about Government or Language Schools?', 'متاكد حكومي او لغات؟'],
    credentialRetry: ['Start solving now (no queue)', 'أبدا الحل مباشرة (بدون طابور)'],
    rateLimited: ['You’re clicking too quickly — wait 10–20 seconds and try again.', 'انت بتضغط بسرعة ، استني 10-20 ثانية وجرب تاني'],
    connectionSlow: ['Connection is slow — retrying automatically.', 'الاتصال بطيء — بنعيد المحاولة تلقائيًا.'],
    readProgressError: ['Unable to read progress.', 'تعذر قراءة التقدم.'],
    startError: ['Unable to start the solve.', 'تعذر بدء الحل.'],
    serverBusy: ['The server is busy — please try again in a few seconds.', 'السيرفر مشغول — حاول تاني بعد ثواني.'],
    events: ['events', 'أحداث'],
    chapter: ['Chapter', 'الفصل'],
    solved: ['solved', 'تم حله'],
  };

  function t(key, values = {}) {
    let value = TEXT[key]?.[uiLanguage === 'en' ? 0 : 1] ?? key;
    for (const [name, replacement] of Object.entries(values)) value = value.replaceAll(`{${name}}`, replacement);
    return value;
  }

  async function readApiJson(response, fallbackKey = 'startError') {
    const body = await respons