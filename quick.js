/* quick.js — FAST SOLVING (Vodafone Cash, auto-verified) for the QUREO public site.
   External file by design: CSP allows 'self' only (+ one pinned inline hash) — no inline JS.
   Flow: plan -> order (phone) -> poll until the SMS webhook
   auto-approves -> pick track/course -> start -> live logs until done. */
(function () {
  'use strict';

  var HEADERS = { 'X-Qureo-Browser': '1' };
  var STORAGE_KEY = 'q-quick-code';
  var WALLET = '01035399218';
  var PLANS = {
    course: { kind: 'solve', label: 'كورس واحد', price: 15, hint: 'جافاسكربت أولى أو تانية أو بايثون', courses: ['gov_js_first', 'gov_js_second', 'gov_py', 'lang_js_first', 'lang_js_second', 'lang_py'] },
    culture: { kind: 'solve', label: 'ثقافة مالية فقط', price: 20, hint: 'الحل الكامل للثقافة المالية', courses: ['gov_fin', 'lang_fin'] },
    full: { kind: 'solve', label: 'تانية بكالوريا كامل', price: 30, hint: 'جافاسكربت + بايثون + ثقافة مالية', courses: ['gov_full', 'lang_full'] },
    vip5: { kind: 'vip', label: 'حساب VIP يحل 5 طلاب', price: 50, accounts: 5 },
    vip10: { kind: 'vip', label: 'حساب VIP يحل 10 طلاب', price: 80, accounts: 10 },
    vip35: { kind: 'vip', label: 'حساب VIP يحل 35 طالب', price: 250, accounts: 35 },
    vip50: { kind: 'vip', label: 'حساب VIP يحل 50 طالب', price: 325, accounts: 50 },
    vip100: { kind: 'vip', label: 'حساب VIP يحل 100 طالب', price: 600, accounts: 100 }
  };
  var COURSE_LABELS = {
    gov_js_first: 'جافاسكربت أولى (حكومي)', gov_js_second: 'جافاسكربت تانية (حكومي)', gov_py: 'بايثون (حكومي)',
    gov_fin: 'ثقافة مالية (حكومي)', gov_full: 'تانية بكالوريا كامل (حكومي)',
    lang_js_first: 'جافاسكربت أولى (لغات)', lang_js_second: 'جافاسكربت تانية (لغات)', lang_py: 'بايثون (لغات)',
    lang_fin: 'ثقافة مالية (لغات)', lang_full: 'تانية بكالوريا كامل (لغات)'
  };
  var TRACKS = { gov: ['gov_js_first', 'gov_js_second', 'gov_py', 'gov_fin', 'gov_full'], lang: ['lang_js_first', 'lang_js_second', 'lang_py', 'lang_fin', 'lang_full'] };

  var state = { plan: '', code: '', track: 'gov', pollTimer: null, pollBusy: false, finished: false, accounts: [], expiresAt: 0 };
  var countdownTimer = null;

  /* ---------- 45-minute payment window (live countdown) ----------
     The order is valid for 45 minutes. The customer sees the clock ticking;
     at zero the order is expired - a late transfer is recovered by opening a
     NEW order (which auto-claims the payment) or by contacting the admin. */
  function expiredGuidance() {
    return 'انتهى وقت الطلب — مضت أكتر من 45 دقيقة من غير ما التحويل يوصلنا. ' +
      'لو كنت حوّلت فعلاً: اضغط زر «طلب جديد» تحت واكتب نفس رقم فودافون — الطلب هيتفعّل فورًا من غير ما تدفع تاني. ' +
      'ولو لسه محوّلتش: اعمل طلب جديد وحوّل على طول، أو كلّم الادارة على تيليجرام لو محتاج مساعدة.';
  }
  function fmtClock(sec) {
    var m = Math.floor(sec / 60), s = sec % 60;
    return m + ':' + (s < 10 ? '0' : '') + s;
  }
  function stopCountdown() {
    if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
    var el = $('quick-countdown');
    if (el) { el.textContent = ''; el.classList.remove('urgent'); }
  }
  function updateCountdown() {
    if (!state.expiresAt) return;
    var left = Math.ceil((state.expiresAt - Date.now()) / 1000);
    var el = $('quick-countdown');
    if (left > 0 && el) {
      el.textContent = left > 300
        ? '⏳ فاضل ' + fmtClock(left) + ' دقيقة على انتهاء صلاحية الطلب — ابعت التحويل قبلها.'
        : '🔴 آخر ' + fmtClock(left) + ' دقيقة! ابعت التحويل دلوقتي.';
      el.classList.toggle('urgent', left <= 300);
    }
    if (left > 0) return;
    stopCountdown();
    setText('quick-expired-text', expiredGuidance());
    goStep('expired');
    try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
    renderResume();
    /* keep a slow poll: money that lands seconds late still approves the
       order - the poll flips the step back to solve/vip by itself */
    startPolling(10000);
  }
  function startCountdown(expiresAtMs) {
    stopCountdown();
    state.expiresAt = expiresAtMs;
    updateCountdown();
    countdownTimer = setInterval(updateCountdown, 1000);
  }

  function $(id) { return document.getElementById(id); }
  function show(el) { if (el) el.classList.remove('hidden'); }
  function hide(el) { if (el) el.classList.add('hidden'); }
  function setText(id, text) { var el = $(id); if (el) el.textContent = text; }

  /* ---------- API ---------- */
  function api(url, options) {
    return fetch(url, Object.assign({ headers: Object.assign({ 'Content-Type': 'application/json' }, HEADERS) }, options || {}))
      .then(function (r) { return r.json().catch(function () { return { ok: false, error: 'السيرفر مش راضي يرد — جرب تاني.' }; }); });
  }

  /* ---------- shared clipboard ---------- */
  function copyText(text, done) {
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, done);
    else {
      var ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); } catch (e) {}
      document.body.removeChild(ta); done();
    }
  }

  /* ---------- modal plumbing ---------- */
  function modal() { return $('quick-modal'); }
  function openModal() { var m = modal(); if (m) { m.classList.remove('hidden'); document.body.style.overflow = 'hidden'; } }
  function closeModal() {
    var m = modal(); if (m) m.classList.add('hidden');
    document.body.style.overflow = '';
    stopPolling();
    stopCountdown();
  }

  function goStep(name) {
    var steps = document.querySelectorAll('#quick-modal [data-quick-step]');
    for (var i = 0; i < steps.length; i++) steps[i].classList.toggle('active', steps[i].getAttribute('data-quick-step') === name);
    var walletBox = $('quick-wallet-box');
    if (walletBox) walletBox.classList.toggle('hidden', name === 'solve' || name === 'run' || name === 'accounts' || name === 'vip-packs');
    var m = modal();
    if (m) { var card = m.querySelector('.modal-card'); if (card) card.scrollTop = 0; }
  }

  function message(id, text, kind) {
    var el = $(id); if (!el) return;
    el.textContent = text || '';
    el.classList.remove('success', 'error');
    if (kind) el.classList.add(kind);
  }

  /* ---------- step 1: order ---------- */
  function openPlan(planId) {
    state.plan = planId; state.code = ''; state.finished = false;
    var plan = PLANS[planId];
    if (!plan) return;
    setText('quick-plan-name', plan.label);
    setText('quick-plan-price', plan.price + ' جنيه');
    setText('quick-plan-hint', plan.hint);
    setText('quick-pending-price', plan.price + ' جنيه');
    setText('quick-wallet-number', WALLET);
    setText('quick-pending-wallet', WALLET);
    message('quick-order-message', '');
    goStep('order');
    openModal();
  }

  function submitOrder(event) {
    event.preventDefault();
    var phoneInput = $('quick-phone');
    var phone = (phoneInput && phoneInput.value || '').replace(/[\u0660-\u0669]/g, function (d) { return String('٠١٢٣٤٥٦٧٨٩'.indexOf(d)); }).replace(/\D/g, '');
    if (!/^01\d{9}$/.test(phone)) { message('quick-order-message', 'اكتب رقم فودافون كامل صح (11 رقم يبدأ بـ 01) — الرقم اللي هتحوّل منه.', 'error'); return; }
    var button = $('quick-order-button');
    if (button) button.disabled = true;
    message('quick-order-message', 'جاري إنشاء الطلب…');
    api('/api/quick/order', { method: 'POST', body: JSON.stringify({ plan: state.plan, phone: phone }) }).then(function (res) {
      if (button) button.disabled = false;
      if (!res.ok) { message('quick-order-message', res.error || 'حصل خطأ — جرب تاني.', 'error'); return; }
      state.code = res.code;
      try { localStorage.setItem(STORAGE_KEY, res.code); } catch (e) {}
      try { localStorage.setItem('q-quick-phone', phone); } catch (e) {}
      renderResume();
      setText('quick-code-display', res.code);
      message('quick-pending-note', 'ابعت ' + res.price + ' جنيه من رقم ' + phone + ' على ' + WALLET + ' في خلال 45 دقيقة. أول ما التحويل يوصل، التأكيد بيتم تلقائي خلال لحظات — سيب الصفحة مفتوحة.');
      goStep('pending');
      startCountdown(Date.now() + (typeof res.expires_in === 'number' && res.expires_in > 0 ? res.expires_in * 1000 : 45 * 60 * 1000));
      startPolling(4000);
    }).catch(function () {
      if (button) button.disabled = false;
      message('quick-order-message', 'النت ضعيف — جرب تاني.', 'error');
    });
  }

  /* ---------- step 2: pending -> approved (SMS webhook) ---------- */
  function startPolling(interval) {
    stopPolling();
    state.finished = false;
    (function tick() {
      if (state.pollBusy) return;
      state.pollBusy = true;
      pollStatus().then(function (stop) {
        state.pollBusy = false;
        if (!stop && !state.finished) state.pollTimer = setTimeout(tick, interval);
      });
    })();
  }
  function stopPolling() { if (state.pollTimer) { clearTimeout(state.pollTimer); state.pollTimer = null; } }

  function pollStatus() {
    if (!state.code) return Promise.resolve(true);
    return api('/api/quick/status?code=' + encodeURIComponent(state.code), { headers: HEADERS })
      .then(function (res) {
        if (!res.ok) { message('quick-pending-note', res.error || 'مش قادرين نوصل للطلب دلوقتي — هنكمل محاولة.', 'error'); return false; }
        if (res.run) { stopCountdown(); return handleRun(res); } /* a run trumps everything - never flip back to solve while solving */
        if (res.status === 'approved') { stopCountdown(); onApproved(res); return true; }
        if (res.status === 'expired') {
          stopCountdown();
          setText('quick-expired-text', expiredGuidance());
          goStep('expired');
          try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
          return true;
        }
        return false; /* still pending */
      }).catch(function () { return false; });
  }

  function onApproved(res) {
    state.plan = res.plan || state.plan;
    var plan = PLANS[state.plan] || {};
    if (plan.kind === 'vip' || res.plan_kind === 'vip') { renderAccounts(res); goStep('accounts'); return; }
    setText('quick-approved-plan', plan.label || '');
    populateCourses();
    goStep('solve');
    message('quick-solve-message', '');
  }

  /* ---------- VIP pack: render the auto-created account ---------- */
  function renderAccounts(res) {
    setText('quick-accounts-plan', 'الباقة: ' + (res.plan_label || (PLANS[state.plan] || {}).label || ''));
    state.accounts = res.accounts || [];
    var solves = res.solves || ((state.accounts[0] || {}).solves) || ((PLANS[state.plan] || {}).accounts) || 0;
    setText('quick-accounts-solves', solves ? 'الحساب ده يقدر يحل ' + solves + ' طالب — كل طالب بالكورس بتاعه، من غير طابور.' : '');
    var pass = state.accounts[0] && state.accounts[0].password;
    setText('quick-password-display', pass || 'مش متاح — ابعتلنا كود الطلب على تيليجرام');
  }

  /* ---------- step 3: solve ---------- */
  function populateCourses() {
    var select = $('quick-course');
    if (!select) return;
    select.innerHTML = '';
    var plan = PLANS[state.plan] || { courses: [] };
    var allowed = plan.courses.filter(function (c) { return TRACKS[state.track].indexOf(c) !== -1; });
    if (!allowed.length) allowed = plan.courses.filter(function (c) { return c.indexOf(state.track + '_') === 0; });
    for (var i = 0; i < allowed.length; i++) {
      var option = document.createElement('option');
      option.value = allowed[i];
      option.textContent = COURSE_LABELS[allowed[i]] || allowed[i];
      select.appendChild(option);
    }
    var single = allowed.length === 1;
    if (single) select.value = allowed[0];
  }

  function setTrack(track) {
    state.track = track;
    var tabs = document.querySelectorAll('#quick-modal [data-quick-track]');
    for (var i = 0; i < tabs.length; i++) tabs[i].classList.toggle('active', tabs[i].getAttribute('data-quick-track') === track);
    populateCourses();
  }

  function submitSolve(event) {
    event.preventDefault();
    var course = $('quick-course') && $('quick-course').value;
    var id = ($('quick-id') && $('quick-id').value || '').trim();
    var pass = $('quick-password') && $('quick-password').value || '';
    if (!id || !pass) { message('quick-solve-message', 'اكتب كود الطالب وكلمة السر بتاعتهم على كيريو.', 'error'); return; }
    var button = $('quick-solve-button');
    if (button) button.disabled = true;
    hide($('quick-retry-solve'));
    var prevFinal = $('quick-run-final');
    if (prevFinal) prevFinal.classList.add('hidden');
    message('quick-solve-message', 'بنشغّل الحل السريع…');
    api('/api/quick/solve', { method: 'POST', body: JSON.stringify({ code: state.code, course: course, id: id, password: pass }) })
      .then(function (res) {
        if (button) button.disabled = false;
        if (!res.ok) {
          if (res.code === 'TOKEN_INVALID') { message('quick-solve-message', 'انتهت جلسة التحقق — اقفل المودال وافتح الصفحة من جديد.', 'error'); return; }
          message('quick-solve-message', res.error || 'حصل خطأ — جرب تاني.', 'error');
          return;
        }
        setText('quick-run-course', res.course_label || '');
        setText('quick-run-count', '0');
        var log = $('quick-run-log'); if (log) log.textContent = 'بنجهز الحل… لحظات ويبدأ النشاط هنا.';
        goStep('run');
        startPolling(3000);
      }).catch(function () {
        if (button) button.disabled = false;
        message('quick-solve-message', 'النت ضعيف — جرب تاني.', 'error');
      });
  }

  /* ---------- step 4: run ---------- */
  function handleRun(res) {
    var run = res.run || {};
    var log = $('quick-run-log');
    if (log && Array.isArray(run.logs)) log.textContent = run.logs.join('\n');
    var progress = res.progress;
    var done = progress && Array.isArray(progress.completed) ? progress.completed.length : 0;
    setText('quick-run-count', String(done));
    var badge = $('quick-run-badge');
    if (run.running) { if (badge) { badge.textContent = 'شغّال الآن'; badge.className = 'running-badge active'; } return false; }
    state.finished = true;
    var final = $('quick-run-final');
    if (final) final.classList.remove('hidden', 'success', 'error');
    if (run.exit === 0) {
      if (badge) { badge.textContent = 'اتخلص ✓'; badge.className = 'running-badge quick-done'; }
      hide($('quick-retry-solve'));
      if (final) { final.textContent = 'خلص الحل! 🎉 افتح حسابك على كيريو وشوف الكورس متحل بالكامل.'; final.classList.add('success'); }
    } else {
      if (badge) { badge.textContent = 'اتوقف'; badge.className = 'running-badge quick-stopped'; }
      var attempts = typeof res.attempts === 'number' ? res.attempts : 0;
      var left = typeof res.attempts_left === 'number' ? res.attempts_left : 0;
      var retryButton = $('quick-retry-solve');
      if (final) {
        if (left > 0) {
          var supportNote = attempts >= 3
            ? ' جربت ' + attempts + ' مرات — لو البيانات صح وبرضه مش شغال، كلم الدعم على تيليجرام وابعت كود طلبك: ' + state.code + '.'
            : '';
          final.textContent = 'الحل وقف قبل ما يخلص — غالبًا كود الطالب أو كلمة السر غلط، أو نوع المدرسة مش مطابق لحسابك. راجع البيانات واكتبها هنا تاني وهيتحل على طول، بس اتأكد 100% إن الكود وكلمة السر صح.' + supportNote;
          final.classList.add('error');
          if (retryButton) {
            retryButton.textContent = '🔄 جرب تاني — اكتب البيانات صح';
            show(retryButton);
          }
        } else {
          final.textContent = 'الحل وقف مرات كتير — كلم الادارة على تيليجرام وابعت كود طلبك: ' + state.code + ' وهما هيتابعوا معاك.';
          final.classList.add('error');
          if (retryButton) hide(retryButton);
        }
      }
    }
    hide($('quick-run-hint'));
    show($('quick-new-order'));
    return true;
  }

  /* ---------- resume chip ---------- */
  function renderResume() {
    var chip = $('quick-resume');
    var code = null;
    try { code = localStorage.getItem(STORAGE_KEY); } catch (e) {}
    if (!code) { hide(chip); return; }
    setText('quick-resume-code', code);
    show(chip);
  }

  function resumeByCode(code) {
    code = (code || '').trim().toUpperCase();
    if (!/^QS[A-Z0-9]{5}$/.test(code)) { message('quick-order-message', 'الكود شكله غلط — الكود بيبدأ بـ QS وبعده 5 حروف/أرقام.', 'error'); return; }
    state.code = code;
    api('/api/quick/status?code=' + encodeURIComponent(code), { headers: HEADERS })
      .then(function (res) {
        if (!res.ok) { message('quick-order-message', res.error || 'الطلب ده مش موجود.', 'error'); goStep('order'); openModal(); return; }
        state.plan = res.plan || state.plan;
        try { localStorage.setItem(STORAGE_KEY, code); } catch (e) {}
        if (res.run) {
          setText('quick-run-course', (res.run || {}).course_label || '');
          handleRun(res);
          if (!state.finished) startPolling(3000);
          goStep('run');
        } else if (res.status === 'approved') {
          onApproved(res);
        } else if (res.status === 'expired') {
          stopCountdown();
          setText('quick-expired-text', 'الطلب ده انتهى (45 دقيقة من غير تأكيد التحويل). لو كنت حوّلت فعلاً — اعمل طلب جديد بنفس رقم فودافون وهيتفعّل فورًا من غير دفع تاني.');
          goStep('expired');
          try { localStorage.removeItem(STORAGE_KEY); } catch (e) {}
        } else {
          setText('quick-code-display', code);
          var price = res.price != null ? res.price : ((PLANS[state.plan] || {}).price != null ? PLANS[state.plan].price : '');
          setText('quick-pending-price', String(price));
          message('quick-pending-note', 'لسه مستنيين تأكيد التحويل. حوّلت؟ التأكيد بيتتم تلقائي خلال لحظات.');
          goStep('pending');
          if (typeof res.expires_in === 'number' && res.expires_in > 0) startCountdown(Date.now() + res.expires_in * 1000);
          else stopCountdown(); /* server without expires_in yet: no clock, the poll still owns expiry */
          startPolling(4000);
        }
        renderResume();
        openModal();
      });
  }

  /* ---------- boot ---------- */
  function bind() {
    var plans = document.querySelectorAll('[data-quick-plan]');
    for (var i = 0; i < plans.length; i++) plans[i].addEventListener('click', function () { openPlan(this.getAttribute('data-quick-plan')); });

    var vipButton = $('quick-vip-button');
    if (vipButton) vipButton.addEventListener('click', function () {
      state.plan = ''; state.code = ''; state.finished = false;
      goStep('vip-packs');
      openModal();
    });

    var packs = document.querySelectorAll('[data-quick-pack]');
    for (var p = 0; p < packs.length; p++) packs[p].addEventListener('click', function () { openPlan(this.getAttribute('data-quick-pack')); });

    var orderForm = $('quick-order-form');
    if (orderForm) orderForm.addEventListener('submit', submitOrder);

    /* last-used wallet number: the expired->retry flow is then one tap */
    var savedPhone = null;
    try { savedPhone = localStorage.getItem('q-quick-phone'); } catch (e) {}
    var phoneField = $('quick-phone');
    if (phoneField && savedPhone) phoneField.value = savedPhone;

    var tabs = document.querySelectorAll('#quick-modal [data-quick-track]');
    for (var t = 0; t < tabs.length; t++) tabs[t].addEventListener('click', function () { setTrack(this.getAttribute('data-quick-track')); });

    var solveForm = $('quick-solve-form');
    if (solveForm) solveForm.addEventListener('submit', submitSolve);

    var solveRetry = $('quick-retry-solve');
    if (solveRetry) solveRetry.addEventListener('click', function () {
      state.finished = false;
      hide(solveRetry);
      var finalBox = $('quick-run-final');
      if (finalBox) finalBox.classList.add('hidden');
      var runBadge = $('quick-run-badge');
      if (runBadge) { runBadge.textContent = ''; runBadge.className = 'running-badge'; }
      goStep('solve');
      message('quick-solve-message', 'اتأكد إن كود الطالب وكلمة السر صح 100% (نفس الحروف بالظبط، من غير مسافات زيادة)، وبعدها اضغط «ابدأ الحل السريع».');
      var passInput = $('quick-password');
      if (passInput) passInput.focus();
    });

    var close = $('quick-close');
    if (close) close.addEventListener('click', closeModal);
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && modal() && !modal().classList.contains('hidden')) closeModal(); });

    var copy = $('quick-copy-wallet');
    if (copy) copy.addEventListener('click', function () {
      copyText(WALLET, function () { message('quick-order-message', 'اتنسخ الرقم ✓ افتح تطبيق فودافون كاش وحوّل.', 'success'); });
    });

    var copyPass = $('quick-accounts-copy');
    if (copyPass) copyPass.addEventListener('click', function () {
      var pass = state.accounts[0] && state.accounts[0].password;
      if (!pass) return;
      copyText(pass, function () {
        copyPass.textContent = 'اتنسخ ✓';
        message('quick-accounts-message', 'اتنسخت ✓ افتح /vip0101 وسجل بيها.', 'success');
        setTimeout(function () { copyPass.textContent = 'نسخ'; }, 1600);
      });
    });

    var resumeButton = $('quick-resume-button');
    if (resumeButton) resumeButton.addEventListener('click', function () { resumeByCode($('quick-resume-code') && $('quick-resume-code').textContent || localStorage.getItem(STORAGE_KEY)); });

    var resumeInput = $('quick-resume-input');
    if (resumeInput) {
      resumeInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') resumeByCode(resumeInput.value); });
      var resumeGo = $('quick-resume-go');
      if (resumeGo) resumeGo.addEventListener('click', function () { resumeByCode(resumeInput.value); });
    }

    var retry = $('quick-expired-retry');
    if (retry) retry.addEventListener('click', function () { openPlan(state.plan || 'course'); });

    var restart = $('quick-new-order');
    if (restart) restart.addEventListener('click', function () { openPlan(state.plan || 'course'); });

    renderResume();

    /* gentle background check so the resume chip shows the right state after verify */
    var tries = 0;
    (function check() {
      var code = null;
      try { code = localStorage.getItem(STORAGE_KEY); } catch (e) {}
      if (!code || tries++ > 6) return;
      api('/api/quick/status?code=' + encodeURIComponent(code), { headers: HEADERS })
        .then(function (res) {
          if (res.ok && (res.run || res.status !== 'pending')) renderResume();
          if (!res.ok && res.code === 'TOKEN_INVALID') setTimeout(check, 5000);
        }).catch(function () {});
    })();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', bind);
  else bind();
})();
