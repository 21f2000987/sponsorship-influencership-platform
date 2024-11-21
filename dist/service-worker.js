self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open('your-cache-name').then((cache) => {
      return cache.addAll([
        '/', // My app's shell
        '/index.html',
        '/styles.css',
        '/script.js',
        '/icons/icon-512x512.png',
        '/icons/icon-192x192.png'
        
      ]);
    })
  );
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request);
    })
  );
});
