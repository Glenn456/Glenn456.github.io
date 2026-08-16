---
layout: null
permalink: /sw.js
---

/*
 * Kill switch.
 *
 * The site used to ship a caching service worker. Browsers that registered it
 * keep serving stale HTML forever, because the cached page is handed back
 * before the network is ever consulted.
 *
 * A browser holding an old registration re-fetches this URL on its update
 * check. This replacement installs, wipes every cache, unregisters itself,
 * and reloads any open tab. After that the site behaves like an ordinary
 * static site again.
 */

self.addEventListener('install', function () {
  self.skipWaiting();
});

self.addEventListener('activate', function (event) {
  event.waitUntil(
    (async function () {
      try {
        const keys = await caches.keys();
        await Promise.all(keys.map(function (k) { return caches.delete(k); }));
      } catch (e) { /* nothing to clear */ }

      try {
        await self.registration.unregister();
      } catch (e) { /* already gone */ }

      try {
        const clients = await self.clients.matchAll({ type: 'window' });
        clients.forEach(function (c) {
          if ('navigate' in c) c.navigate(c.url);
        });
      } catch (e) { /* tab will pick it up on next load */ }
    })()
  );
});

/* Never serve from cache while this is active. */
self.addEventListener('fetch', function (event) {
  event.respondWith(fetch(event.request));
});
