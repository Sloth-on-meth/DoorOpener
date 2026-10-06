/* DoorOpener Service Worker */
const CACHE_VERSION = 'v3'; // bump on every deploy to bust stale caches
const CACHE_NAME = `dooropener-cache-${CACHE_VERSION}`;
const ASSETS = [
  '/',
  '/static/background.jpg',
  '/static/favicon.png',
  '/static/gear.png',
  '/manifest.webmanifest'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.map((key) => (key !== CACHE_NAME ? caches.delete(key) : undefined)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Only handle same-origin GET requests
  if (req.method !== 'GET' || url.origin !== self.location.origin) {
    return; // let the browser handle it normally
  }

  // For the app shell (root), prefer network but fallback to cache
  if (url.pathname === '/') {
    event.respondWith(
      fetch(req).then((res) => {
        const resClone = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
        return res;
      }).catch(() => caches.match(req))
    );
    return;
  }

  // For static assets, use cache-first
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(
      caches.match(req).then((cached) => cached || fetch(req).then((res) => {
        const resClone = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
        return res;
      }))
    );
    return;
  }

  // Everything else (/admin/*, /auth/status, /battery, ...) goes straight to the network and is
  // never cached: those responses hold user lists, audit logs and auth state that must not
  // persist in Cache Storage or be replayed offline after logout.
  return;
});
