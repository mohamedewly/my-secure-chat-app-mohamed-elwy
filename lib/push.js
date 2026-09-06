// Browser push notifications via the standard Push API + VAPID.
//
// Important privacy note: because messages are end-to-end encrypted, the
// server never has plaintext to put in a push payload. Pushes are
// intentionally generic ("New message in <room>") — they never leak
// message content, matching the same privacy guarantee as everything else
// in this app.

const webpush = require('web-push');

let configured = false;
function ensureConfigured() {
  if (configured) return;
  const { VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT } = process.env;
  if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
    throw new Error(
      'VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY are not set. Generate a pair with: npm run gen-vapid'
    );
  }
  webpush.setVapidDetails(
    VAPID_SUBJECT || 'mailto:admin@example.com',
    VAPID_PUBLIC_KEY,
    VAPID_PRIVATE_KEY
  );
  configured = true;
}

/**
 * Sends a push notification. Returns { ok: true } on success, or
 * { ok: false, gone: true } if the subscription is dead (410/404 — the
 * caller should delete it), or { ok: false, error } for other failures.
 */
async function sendPush(subscription, payloadObj) {
  ensureConfigured();
  try {
    await webpush.sendNotification(subscription, JSON.stringify(payloadObj));
    return { ok: true };
  } catch (e) {
    const gone = e.statusCode === 404 || e.statusCode === 410;
    return { ok: false, gone, error: e.message };
  }
}

module.exports = { sendPush };
