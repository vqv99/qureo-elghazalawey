# QUREO Elghazalawy — ملخص المشروع

## ما هو المشروع؟

موقع ويب يحل كورسات QUREO تلقائياً للطلاب.  
المستخدم بيدخل كود الطالب وكلمة السر، والسيرفر بيفتح متصفح ويكمل الكورس لوحده.

---

## الملفات

| الملف | الوظيفة |
|---|---|
| `index.html` | الواجهة الكاملة للموقع |
| `styles.css` | التصميم |
| `app.js` | منطق الواجهة (اختيار كورس، validation، متابعة التقدم) |
| `quick.js` | نظام الحل السريع |
| `server.js` | السيرفر الكامل — Express + كل الـ APIs |
| `scripts/solver_core.js` | مكتبة مشتركة للتحكم في المتصفح |
| `scripts/gov_js_first.js` | إجابات JavaScript أولى ثانوي حكومي |
| `scripts/gov_js_second.js` | إجابات JavaScript تانية ثانوي حكومي |
| `scripts/lang_js_first.js` | إجابات JavaScript أولى — لغات |
| `scripts/lang_js_second.js` | إجابات JavaScript تانية — لغات |
| `scripts/gov_py.js` | إجابات Python — حكومي |
| `scripts/lang_py.js` | إجابات Python — لغات |
| `scripts/gov_fin.js` | إجابات ثقافة مالية — حكومي |
| `scripts/lang_fin.js` | إجابات ثقافة مالية — لغات |
| `START.bat` | تشغيل السيرفر محلياً بـ double-click |
| `package.json` | dependencies (express + puppeteer) |

---

## الـ APIs

| Endpoint | الوظيفة |
|---|---|
| `GET /api/health` | حالة السيرفر |
| `GET /api/browser/challenge` | PoW challenge للحماية |
| `POST /api/browser/verify` | تحقق من المتصفح |
| `GET /api/progress` | متابعة تقدم الحل لحظة بلحظة |
| `POST /api/solve` | بدء حل جديد |
| `POST /api/vip0101/login` | دخول لوحة VIP |
| `GET /api/vip0101/session` | استعادة جلسة VIP |
| `POST /api/vip0101/start` | بدء حل من لوحة VIP |
| `POST /api/vip0101/status` | حالة كل الحلول الشغّالة |

---

## الكورسات المدعومة

| الكود | الكورس |
|---|---|
| `js_fast_42` | JavaScript أولى — حكومي |
| `jslangs_fast_42` | JavaScript أولى — لغات |
| `js_fast` | JavaScript تانية — حكومي |
| `jslangs_fast` | JavaScript تانية — لغات |
| `pylangs_fast` | Python — حكومي |
| `pylangs` | Python — لغات |
| `fin` | ثقافة مالية — حكومي |
| `sakafa_langs` | ثقافة مالية — لغات |

---

## التغييرات اللي اتعملت

- ✅ الاسم اتغيّر لـ **QUREO Elghazalawy** في كل مكان
- ✅ رابط Telegram اتمسح
- ✅ خطوة الاشتراك في تيليجرام اتمسحت (الموقع بيفتح مباشرة)
- ✅ سكشن فودافون كاش اتمسح
- ✅ Validation شغّال على كود الطالب وكلمة السر ورقم الموبايل
- ✅ كلمة سر VIP: `vip1234` (قابلة للتغيير)

---

---

# خطوات الرفع على Railway عن طريق GitHub

## المتطلبات
- حساب GitHub: [github.com](https://github.com)
- حساب Railway: [railway.app](https://railway.app)

---

## الخطوة 1 — جهّز الملفات للرفع

افتح `package.json` وتأكد إن فيه السطر ده:

```json
"scripts": {
  "start": "node server.js"
}
```

أنشئ ملف `.gitignore` في مجلد المشروع وحط فيه:

```
node_modules/
data.json
*.log
*.txt
*.bat
```

---

## الخطوة 2 — ارفع على GitHub

افتح CMD في مجلد المشروع وشغّل:

```bash
git init
git add .
git commit -m "first commit"
```

روح على [github.com/new](https://github.com/new) وأنشئ repo جديد اسمه `qureo-elghazalawy` (**private**).

بعدين في CMD:

```bash
git remote add origin https://github.com/YOUR_USERNAME/qureo-elghazalawy.git
git branch -M main
git push -u origin main
```

> استبدل `YOUR_USERNAME` باسم حسابك على GitHub.

---

## الخطوة 3 — ارفع على Railway

1. روح على [railway.app](https://railway.app) وسجّل دخول بحساب GitHub
2. اضغط **New Project**
3. اختار **Deploy from GitHub repo**
4. اختار الـ repo اللي عملته `qureo-elghazalawy`
5. Railway هيلاقي `package.json` ويبدأ الـ deploy تلقائي

---

## الخطوة 4 — ضبط Environment Variables

في Railway افتح المشروع ← **Variables** ← أضف:

| Variable | Value |
|---|---|
| `VIP_PASSWORD` | كلمة سر VIP اللي عايزها |
| `PORT` | `3000` |

---

## الخطوة 5 — ضبط الـ Puppeteer على Railway

Railway بيحتاج Chrome يتنزّل مع الـ build. أضف variable:

| Variable | Value |
|---|---|
| `PUPPETEER_SKIP_CHROMIUM_DOWNLOAD` | `false` |

وأضف ملف `nixpacks.toml` في المشروع:

```toml
[phases.setup]
nixPkgs = ["chromium", "nss", "freetype", "harfbuzz", "ca-certificates", "ttf-dejavu"]
```

---

## الخطوة 6 — احصل على الرابط

بعد ما الـ deploy يخلص (2-3 دقايق):

Railway ← **Settings** ← **Domains** ← اضغط **Generate Domain**

هيديك رابط زي:
```
https://qureo-elghazalawy.up.railway.app
```

---

## ملاحظات مهمة

- كل ما تعمل `git push` على GitHub، Railway بيعمل deploy تلقائي
- لو السيرفر وقف، Railway بيشغّله تاني لوحده
- الـ free tier على Railway = **500 ساعة في الشهر** (كافية لبداية الشغل)
- لو الطلب كتر، اترقّى للـ **Starter plan بـ 5 دولار / شهر**
