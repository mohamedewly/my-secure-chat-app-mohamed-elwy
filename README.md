# Secure Chat — full feature set

Real-time encrypted chat with accounts, rooms, admin controls, polls, files,
reactions, replies, edit/delete, typing indicators, read receipts, invite
links, avatars, search, and two kinds of notifications.

## Encryption model (unchanged from earlier, still the foundation)

1. **Client-side end-to-end.** Every message — text, poll, vote, reaction,
   edit, delete, read receipt, file metadata — is JSON encrypted in the
   browser with AES-256-GCM, keyed by a passphrase you share out-of-band.
   The server never sees this key or any plaintext content.
2. **Server-side at-rest.** Before anything touches MongoDB, the server
   encrypts the whole envelope again with its own key, and decrypts it
   again right after reading it back. A leaked database backup alone is
   useless without that key — and even with it, an attacker only gets the
   E2E ciphertext from layer 1, not the actual content.

Everything below is built on top of that unchanged foundation. New message
*kinds* (`poll`, `vote`, `reaction`, `edit`, `delete`, `read`) all flow
through the exact same generic encrypted-message pipe as plain text — the
server treats them as opaque ciphertext either way.

## What's new in this round

**Message-level:**
- **Emoji reactions** — react to any message; tallied client-side from a stream of encrypted reaction events, so the server never learns who reacted with what.
- **Reply to a specific message** — every message gets a client-generated `msgId`; replies reference it and render a quoted preview.
- **Edit / delete your own messages** — sent as new encrypted `edit`/`delete` events referencing the original `msgId`. Every client independently checks that the event's real, server-verified author matches the original message's author before applying it — so a forged edit/delete claiming to target someone else's message is simply ignored.
- **Typing indicators & read receipts** — typing is a lightweight, unencrypted, unstored WebSocket signal (pure presence, nothing worth encrypting). Read receipts are encrypted messages like everything else, tallied client-side to show "Seen" on your latest message.

**Room / social:**
- **Invite links** — share a room code via URL (`?room=...`). Optionally include the passphrase too (`?pass=...`) if you explicitly opt in via a checkbox — clearly flagged as less secure, since anyone with the link then has full access.
- **Room admins** — the first person to join a room becomes its **owner**; owners can promote members to **admin**. Owners/admins can **mute** (block sending, but they can still read) or **kick** (remove membership entirely, and disconnect their live session if connected) other members. The owner can't be muted or kicked by anyone.
- **Avatars** — pick an emoji + color as your profile badge, shown next to your name throughout a room.
- **Search** — client-side only, over messages already decrypted in your current session. This is a direct, honest consequence of end-to-end encryption: the server cannot search content it can never read, so there's no way to build server-side search without breaking the encryption model. If you need to find something in a room's full history, you have to have loaded that history first (which happens automatically on join).

**Notifications, unchanged from before:** in-app (bell icon, live) and browser push (service worker, arrives even if the site is closed, generic payloads only since the server can't read message content either).

## Important limitation: kicking isn't cryptographic revocation

This is worth understanding clearly. Kicking someone removes their account's
membership record and disconnects their live session — but it does **not**
rotate the room's encryption key. If the kicked person still knows the
passphrase, nothing stops them from typing it into a fresh account and
rejoining, or reading any messages sent to that passphrase from outside this
app entirely. Real access revocation would require rotating the passphrase
and re-sharing it with everyone except the removed person — this app doesn't
automate that. Treat kick/mute as social/moderation tools within trusted
groups, not as a security boundary.

## Setup (same as before — nothing new required for these features)

```bash
npm install
cp .env.example .env
```

Fill in `.env`: `MONGO_URI`, `SERVER_ENCRYPTION_KEY` (`npm run gen-key`),
`JWT_SECRET` (`npm run gen-jwt-secret`), your S3-compatible bucket details,
and `VAPID_PUBLIC_KEY`/`VAPID_PRIVATE_KEY` (`npm run gen-vapid`) if you want
push notifications.

```bash
npm start
```

Open `http://localhost:8080`, sign up, join a room, and everything above is
available in the UI: hover a message for reply/react/edit/delete, the 🔗 for
invite links, 🔍 for search, 👥 for the members/admin panel, and 👤 next to
your name for avatar settings.

## What was tested vs. not

This sandbox has no network access to real MongoDB, S3, or push services, so
those three were tested against in-memory/local stand-ins with identical
function signatures. Everything else was tested for real: **65 checks
across 4 test suites**, run against the live server —

- Registration/login, wrong-password rejection, JWT auth
- Room ownership assignment (first joiner = owner), role promotion/demotion authorization
- Mute enforcement (a muted member's messages are rejected server-side, verified nobody else receives them), and that unmuting restores sending
- Kick: only owners/admins can kick, admins can't kick other admins, the owner can never be kicked/muted, a kicked user is disconnected from the room server-side (not just client-hidden) and can no longer send into it
- File upload authorization scoped to room membership
- Offline notification + push-attempt triggering, in-app notification delivery to online-elsewhere sessions
- **The actual encryption**, using the *real* client crypto functions (extracted verbatim from the client file, run via Node's WebCrypto — the same API browsers use) as multiple simulated independent users: text, polls, votes, file metadata, replies, edits, deletes, reactions, and read receipts all round-trip correctly; a forged edit/delete is correctly attributed to its real (wrong) author so a correct client rejects it; wrong passphrase fails to decrypt everything, every kind, no exceptions
- Typing indicators carry the correct authenticated identity and are never persisted into message history

**Not tested here:** an actual MongoDB write, an actual S3 upload, an actual
push notification landing in a real browser, and the full client UI in an
actual browser (no headless browser available in this sandbox — the crypto
and protocol layer were tested directly instead, which is the part most
likely to hide a real bug; the UI wiring is comparatively low-risk but worth
your own click-through once it's running).

## Project structure

```
secure-chat-server/
├── server.js              Express REST API + WebSocket chat
├── lib/
│   ├── auth.js              password hashing (scrypt) + JWT
│   ├── crypto.js             server-side at-rest encryption layer
│   ├── storage.js            S3 presigned upload/download URLs
│   ├── push.js               web-push wrapper (browser push)
│   ├── db.js                 MongoDB access — users, room membership/roles,
│   │                         messages, notifications, push subscriptions
│   └── *.selftest.js         offline self-tests: npm run test:all
├── public/
│   ├── index.html            the whole client
│   └── sw.js                  service worker for push notifications
├── .env.example
└── package.json
```
