// This runs in the background, separately from the page — it's what lets
// a notification arrive even if the site/tab is closed. It never sees
// message content: the server only ever sends generic payloads like
// "New message in <room>", since messages are end-to-end encrypted and
// the server can't read them either.

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) { /* ignore malformed payload */ }

  const title = data.title || 'New message';
  const options = {
    body: data.body || 'You have new activity.',
    tag: data.room ? ('room-' + data.room) : undefined, // collapse repeats for the same room
    data: { room: data.room },
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow('/');
    })
  );
});
