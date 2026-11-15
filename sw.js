// مصمم الكوثر — يجلب آخر نسخة من الإنترنت دائماً، ويستخدم النسخة المحفوظة فقط عند انقطاع الإنترنت
const CACHE='mlazem-cache';
self.addEventListener('install',e=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',e=>{
  const r=e.request;if(r.method!=='GET')return;
  const u=new URL(r.url);if(u.origin!==self.location.origin)return;
  e.respondWith(fetch(r.url,{cache:'no-store',credentials:'same-origin'}).then(res=>{
    if(res.ok){const cp=res.clone();caches.open(CACHE).then(c=>c.put(r.url.split('?')[0],cp))}
    return res;
  }).catch(()=>caches.match(r.url.split('?')[0])));
});
