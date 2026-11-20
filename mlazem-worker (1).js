// =====================================================================
//  مصمم الكوثر — Worker لحفظ الملفات الكبيرة على Cloudflare R2
//  - الرفع والحذف: حساب المدير فقط (admin@mlazem.app)
//  - التحميل: أي شخص مسجّل دخول بالبرنامج
//  الربط المطلوب (Bindings): R2 bucket باسم المتغير  BUCKET
//  تحويل خط اليد: Secret باسم  GEMINI_KEY  (مفتاح من aistudio.google.com)
//                 واختياري: متغير GEMINI_MODEL (الافتراضي gemini-flash-latest)
// =====================================================================
const PROJECT = 'mlazem-designer';
const ADMIN_EMAIL = 'admin@mlazem.app';
const ORIGINS = ['https://alkwther.github.io'];
const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

let JWKS = null, JWKS_AT = 0;

function cors(req) {
  const o = req.headers.get('Origin') || '';
  return {
    'Access-Control-Allow-Origin': ORIGINS.includes(o) ? o : ORIGINS[0],
    'Access-Control-Allow-Methods': 'GET,PUT,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization,Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  };
}
const json = (req, obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { ...cors(req), 'Content-Type': 'application/json; charset=utf-8' } });

function b64u(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s), out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function keys() {
  if (JWKS && Date.now() - JWKS_AT < 3600e3) return JWKS;
  const r = await fetch(JWKS_URL);
  JWKS = (await r.json()).keys;
  JWKS_AT = Date.now();
  return JWKS;
}

// يتأكد من توكن Firebase ويرجع { uid, email } أو null
async function verify(req) {
  const h = req.headers.get('Authorization') || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  const p = tok.split('.');
  if (p.length !== 3) return null;
  try {
    const head = JSON.parse(new TextDecoder().decode(b64u(p[0])));
    const body = JSON.parse(new TextDecoder().decode(b64u(p[1])));
    const now = Math.floor(Date.now() / 1000);
    if (head.alg !== 'RS256') return null;
    if (body.aud !== PROJECT || body.iss !== 'https://securetoken.google.com/' + PROJECT) return null;
    if (!body.sub || body.exp < now || body.iat > now + 300) return null;
    const jwk = (await keys()).find(k => k.kid === head.kid);
    if (!jwk) return null;
    const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64u(p[2]), new TextEncoder().encode(p[0] + '.' + p[1]));
    return ok ? { uid: body.sub, email: (body.email || '').toLowerCase() } : null;
  } catch (e) { return null; }
}


// ---------- تحويل صفحة خط يد إلى ملزمة ----------
const HW_PROMPT = `أنت تنسخ صفحة ملزمة دراسية عراقية مكتوبة بخط اليد (أو مطبوعة) إلى نص بنفس الكلمات وبنفس مكان كل جزء بالضبط.
القواعد المهمة جداً:
1) انسخ كل كلمة وكل رقم وكل رمز كما هو حرفياً، ولا تترك أي سطر حتى الملاحظات الصغيرة بالأسفل وبالجوانب. لا تصحح، لا تعيد الصياغة، لا تضف، لا تترجم.
2) العربي يبقى عربي والإنكليزي يبقى إنكليزي بنفس الحروف. الأرقام كما هي بالورقة.
3) الرياضيات والعلوم: الجذر √(ما تحت الجذر) مثل √(12) و 2√(3) و ∛(8/27)، الكسر (البسط)/(المقام) دائماً بين قوسين مثل (3√(2) - 2√(3))/(√(27))، الأس ² ³ ⁿ ⁻¹، المؤشر x₁ H₂O، والرموز × ÷ ± ≤ ≥ ≠ ≈ → ⇌ ↑ ↓ ∫ ∑ Δ θ α β λ μ Ω π ∞ °. الخط المائل (شطب الاختصار) تجاهله واكتب الحد كما هو.
4) أي كلمة أو رمز مو متأكد منه 100% حطه بين ⟦ ⟧.
5) قسّم الصفحة إلى أجزاء (blocks) بترتيب القراءة: كل سطر معادلة جزء لوحده، وكل فقرة أو سؤال أو عنوان أو ملاحظة جزء، وكل حساب جانبي جزء. لكل جزء أعطِ box = [ymin, xmin, ymax, xmax] من 0 إلى 1000 يغطيه بالضبط، و n = عدد أسطره، و c = لون الحبر (black أو red أو blue أو green).
6) داخل t استخدم: # عنوان رئيسي، ## عنوان فرعي، - نقطة، 1. ترقيم، **عريض**، {{ملوّن}} لكلمات ملونة داخل سطر أسود، وأسطر متعددة بفاصل سطر جديد. القسمة المتكررة (التحليل للعوامل الأولية) اكتبها جدول: كل سطر | العدد | القاسم |.
7) الرسومات الحقيقية (أشكال هندسية، مخططات، صور، رسوم بيانية) فقط: k = "fig" مع box بدون t. لا تجعل الكتابة أو المعادلات fig.
8) تجاهل الإطار المزخرف حول الصفحة ورقم الصفحة بالأسفل والأسهم والخطوط التوضيحية.
أرجع JSON فقط: {"title":"عنوان الصفحة إن وجد","blocks":[{"k":"t","box":[0,0,0,0],"n":1,"c":"black","t":"..."}]}`;

async function handwriting(req, env, user) {
  if (!env.GEMINI_KEY) return json(req, { error: 'مفتاح Gemini غير مضاف بالـ Worker (GEMINI_KEY)' }, 500);
  let b;
  try { b = await req.json(); } catch (e) { return json(req, { error: 'bad body' }, 400); }
  const img = String(b.image || '');
  if (!img || img.length > 7_000_000) return json(req, { error: 'الصورة فارغة أو كبيرة جداً' }, 400);
  const models = [env.GEMINI_MODEL, 'gemini-flash-latest', 'gemini-2.5-flash', 'gemini-flash-lite-latest', 'gemini-2.5-flash-lite'].filter((m, i, a) => m && a.indexOf(m) === i);
  const body = {
    contents: [{ role: 'user', parts: [{ text: HW_PROMPT + (b.subject ? '\nالمادة: ' + String(b.subject).slice(0, 60) : '') }, { inline_data: { mime_type: b.mime || 'image/jpeg', data: img } }] }],
    generationConfig: { temperature: 0, responseMimeType: 'application/json', maxOutputTokens: 16384 }
  };
  let last = '';const T0 = Date.now();
  // بدون «تفكير» طويل: القراءة أسرع بوايد
  const thinks = m => /gemini-3|latest/.test(m) ? [{ thinkingLevel: 'minimal' }, { thinkingBudget: 0 }, null] : /2\.5/.test(m) ? [{ thinkingBudget: 0 }, null] : [null];
  for (const model of models) {
    let tc = thinks(model), ti = 0;
    for (let a = 0; a < 3; a++) {
      const gc = Object.assign({}, body.generationConfig); if (tc[ti]) gc.thinkingConfig = tc[ti];
      const r = await fetch('https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-goog-api-key': env.GEMINI_KEY }, body: JSON.stringify(Object.assign({}, body, { generationConfig: gc })), signal: AbortSignal.timeout(75000) }).catch(e => null);
      if (!r) { last = 'timeout ' + model; break; }
      const t = await r.text();
      if (r.status === 404) { last = t; break; }
      if (r.status === 400 && ti < tc.length - 1) { ti++; a--; continue; }
      if (r.status === 429 || r.status >= 500) { last = r.status + ' ' + t; if (r.status === 429 && /quota|exhaust|per day|PerDay/i.test(t)) break; if (a >= 1) break; await new Promise(z => setTimeout(z, 2500)); continue; }
      if (!r.ok) return json(req, { error: 'Gemini ' + r.status, detail: t.slice(0, 400) }, 502);
      try {
        const j = JSON.parse(t);
        const txt = ((j.candidates && j.candidates[0] && j.candidates[0].content && j.candidates[0].content.parts) || []).filter(p => !p.thought).map(p => p.text || '').join('');
        let out; try { out = JSON.parse(txt); } catch (e) { const m = txt.match(/\{[\s\S]*\}/); out = m ? JSON.parse(m[0]) : { md: txt }; }
        const blocks = Array.isArray(out.blocks) ? out.blocks : null;
        const md = out.md ? String(out.md) : (blocks ? blocks.filter(x => x.k !== 'fig').map(x => x.t || '').join('\n') : '');
        return json(req, { ok: true, md, blocks, title: String(out.title || ''), model, ms: Date.now() - T0, think: tc[ti] ? JSON.stringify(tc[ti]) : 'on' });
      } catch (e) { return json(req, { error: 'رد غير مفهوم من Gemini' }, 502); }
    }
  }
  const quota = /quota|exhaust|per day|PerDay|^429/i.test(last);
  return json(req, { error: quota ? 'خلص الحد المجاني لقراءة Gemini — جرّب بعد شوية أو فعّل الدفع بحساب Google' : 'خدمة Gemini مشغولة هسه، جرّب بعد دقيقة', detail: last.slice(0, 300) }, 429);
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(req) });
    const url = new URL(req.url);
    if (url.pathname === '/' || url.pathname === '/health')
      return json(req, { ok: true, service: 'mlazem-files', bucket: !!env.BUCKET, hw: !!env.GEMINI_KEY });
    if (url.pathname === '/ai/hw') {
      if (req.method !== 'POST') return json(req, { error: 'method' }, 405);
      const u = await verify(req);
      if (!u) return json(req, { error: 'سجّل الدخول أولاً' }, 401);
      return handwriting(req, env, u);
    }
    if (!env.BUCKET) return json(req, { error: 'R2 bucket غير مربوط — أضف Binding باسم BUCKET' }, 500);

    const m = url.pathname.match(/^\/obj\/([A-Za-z0-9_\-\/.]{1,200})$/);
    if (!m || m[1].includes('..')) return json(req, { error: 'not found' }, 404);
    const key = m[1];

    const user = await verify(req);
    if (!user) return json(req, { error: 'سجّل الدخول أولاً' }, 401);
    const isAdmin = user.email === ADMIN_EMAIL;

    if (req.method === 'GET') {
      const obj = await env.BUCKET.get(key);
      if (!obj) return json(req, { error: 'الملف غير موجود' }, 404);
      return new Response(obj.body, { headers: { ...cors(req), 'Content-Type': obj.httpMetadata?.contentType || 'application/octet-stream', 'Cache-Control': 'private, max-age=60' } });
    }
    if (!isAdmin) return json(req, { error: 'للمدير فقط' }, 403);
    if (req.method === 'PUT') {
      await env.BUCKET.put(key, req.body, { httpMetadata: { contentType: req.headers.get('Content-Type') || 'application/octet-stream' } });
      return json(req, { ok: true, key });
    }
    if (req.method === 'DELETE') {
      await env.BUCKET.delete(key);
      return json(req, { ok: true });
    }
    return json(req, { error: 'method' }, 405);
  }
};
