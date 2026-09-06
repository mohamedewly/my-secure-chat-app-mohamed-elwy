require('dotenv').config();

const http = require('http');
const path = require('path');
const express = require('express');
const { WebSocketServer } = require('ws');

const db = require('./lib/db');
const { encryptAtRest, decryptAtRest } = require('./lib/crypto');
const auth = require('./lib/auth');
const storage = require('./lib/storage');
const push = require('./lib/push');

const PORT = process.env.PORT || 8080;
const PUBLIC_DIR = path.join(__dirname, 'public');
const MAX_ROOM_LEN = 64;
const MAX_MESSAGE_FIELD_LEN = 200000; // ~generous cap for encrypted text/file-metadata payloads
const MAX_UPLOAD_BYTES = 20 * 1024 * 1024; // 20MB, matches the client-side check

// ---------------------------------------------------------------------
// Express app: static client + REST API
// ---------------------------------------------------------------------
const app = express();
app.use(express.json({ limit: '256kb' }));
app.use(express.static(PUBLIC_DIR));

// ---- auth ----

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!auth.validateUsername(username)) {
    return res.status(400).json({ error: 'Username must be 3-24 characters: letters, numbers, _ or -.' });
  }
  if (!auth.validatePassword(password)) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }
  const existing = await db.findUserByUsername(username);
  if (existing) return res.status(409).json({ error: 'That username is already taken.' });

  const passwordHash = auth.hashPassword(password);
  const user = await db.createUser(username, passwordHash);
  const token = auth.signToken({ sub: user._id, username: user.username });
  res.json({ token, username: user.username });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password are required.' });
  }
  const user = await db.findUserByUsername(username);
  if (!user || !auth.verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Incorrect username or password.' });
  }
  const token = auth.signToken({ sub: user._id.toString(), username: user.username });
  res.json({ token, username: user.username });
});

app.get('/api/me', auth.requireAuth, async (req, res) => {
  const user = await db.findUserById(req.userId);
  res.json({
    userId: req.userId,
    username: req.username,
    avatarEmoji: (user && user.avatarEmoji) || null,
    avatarColor: (user && user.avatarColor) || null,
  });
});

// ---- profile (avatar customization) ----

const EMOJI_RE = /^\p{Extended_Pictographic}$/u;

app.post('/api/profile', auth.requireAuth, async (req, res) => {
  const { avatarEmoji, avatarColor } = req.body || {};
  if (avatarEmoji != null && (typeof avatarEmoji !== 'string' || !EMOJI_RE.test(avatarEmoji))) {
    return res.status(400).json({ error: 'avatarEmoji must be a single emoji character.' });
  }
  if (avatarColor != null && (typeof avatarColor !== 'string' || !/^#[0-9a-fA-F]{6}$/.test(avatarColor))) {
    return res.status(400).json({ error: 'avatarColor must be a hex color like #e8a33d.' });
  }
  await db.updateUserProfile(req.userId, { avatarEmoji: avatarEmoji || null, avatarColor: avatarColor || null });
  res.json({ ok: true });
});

// ---- rooms (per-account persisted list) ----

app.get('/api/rooms', auth.requireAuth, async (req, res) => {
  const rooms = await db.getUserRooms(req.userId);
  res.json({ rooms: rooms.map((r) => ({ room: r.room, lastJoinedAt: r.lastJoinedAt })) });
});

// ---- notifications ----

app.get('/api/notifications', auth.requireAuth, async (req, res) => {
  const notifications = await db.getUnreadNotifications(req.userId);
  res.json({
    notifications: notifications.map((n) => ({
      id: n._id.toString(),
      room: n.room,
      kind: n.kind,
      ts: n.ts,
    })),
  });
});

app.post('/api/notifications/read', auth.requireAuth, async (req, res) => {
  const { ids } = req.body || {};
  if (!Array.isArray(ids) || ids.length === 0) return res.status(400).json({ error: 'ids array is required.' });
  await db.markNotificationsRead(req.userId, ids);
  res.json({ ok: true });
});

// ---- push notifications ----

app.get('/api/push/vapid-public-key', (req, res) => {
  if (!process.env.VAPID_PUBLIC_KEY) return res.status(503).json({ error: 'Push is not configured on this server.' });
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

app.post('/api/push/subscribe', auth.requireAuth, async (req, res) => {
  const { subscription } = req.body || {};
  if (!subscription || !subscription.endpoint || !subscription.keys) {
    return res.status(400).json({ error: 'A valid push subscription object is required.' });
  }
  await db.savePushSubscription(req.userId, subscription);
  res.json({ ok: true });
});

app.post('/api/push/unsubscribe', auth.requireAuth, async (req, res) => {
  const { endpoint } = req.body || {};
  if (!endpoint) return res.status(400).json({ error: 'endpoint is required.' });
  await db.removePushSubscriptionByEndpoint(endpoint);
  res.json({ ok: true });
});

// ---- file / image uploads (encrypted client-side; server just brokers S3 access) ----

app.post('/api/upload-url', auth.requireAuth, async (req, res) => {
  const { room, filename, contentType, size } = req.body || {};
  const cleanRoom = String(room || '').slice(0, MAX_ROOM_LEN);
  if (!cleanRoom || !filename) return res.status(400).json({ error: 'room and filename are required.' });
  if (typeof size !== 'number' || size <= 0 || size > MAX_UPLOAD_BYTES) {
    return res.status(400).json({ error: `File must be under ${MAX_UPLOAD_BYTES / (1024 * 1024)}MB.` });
  }
  try {
    const key = storage.buildObjectKey(cleanRoom, filename);
    // Encrypted bytes are opaque ciphertext, so we always upload as application/octet-stream
    // regardless of the original file's type (that type is itself encrypted metadata).
    const uploadUrl = await storage.getUploadUrl(key, 'application/octet-stream');
    res.json({ uploadUrl, key });
  } catch (e) {
    res.status(500).json({ error: 'Could not create an upload URL: ' + e.message });
  }
});

app.get('/api/download-url', auth.requireAuth, async (req, res) => {
  const key = String(req.query.key || '');
  const match = key.match(/^rooms\/([^/]+)\//);
  if (!match) return res.status(400).json({ error: 'Invalid file key.' });
  const room = match[1];
  const member = await db.isRoomMember(req.userId, room);
  if (!member) return res.status(403).json({ error: 'You are not a member of that room.' });
  try {
    const downloadUrl = await storage.getDownloadUrl(key);
    res.json({ downloadUrl });
  } catch (e) {
    res.status(500).json({ error: 'Could not create a download URL: ' + e.message });
  }
});

const server = http.createServer(app);

// ---------------------------------------------------------------------
// WebSocket: live chat (text, polls, votes, file-share metadata — all
// generic encrypted "message" envelopes from the server's point of view)
// ---------------------------------------------------------------------
const wss = new WebSocketServer({ server });

const rooms = new Map(); // room -> Set<ws>          (who's actively viewing which room)
const userSockets = new Map(); // userId -> Set<ws>   (all of a user's open connections, any room)

function addToMap(map, key, ws) {
  if (!map.has(key)) map.set(key, new Set());
  map.get(key).add(ws);
}
function removeFromMap(map, key, ws) {
  const set = map.get(key);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) map.delete(key);
}

function broadcastToRoom(room, payload, exceptWs) {
  const set = rooms.get(room);
  if (!set) return;
  const data = JSON.stringify(payload);
  for (const client of set) {
    if (client !== exceptWs && client.readyState === client.OPEN) client.send(data);
  }
}

function sendToUser(userId, payload) {
  const set = userSockets.get(userId);
  if (!set) return;
  const data = JSON.stringify(payload);
  for (const client of set) {
    if (client.readyState === client.OPEN) client.send(data);
  }
}

function safeSend(ws, payload) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(payload));
}

/**
 * After a message is stored, figure out who else in the room should be
 * told about it: live in-app notification if they're online elsewhere in
 * the app, a persisted notification either way, and a push notification
 * only if they have no open connection to the app at all (so we don't
 * double-notify someone who's actively using it).
 */
async function notifyRoomMembers(room, senderUserId) {
  let memberIds;
  try {
    memberIds = await db.getRoomMemberIds(room);
  } catch (e) {
    return;
  }
  const viewingRoom = rooms.get(room) || new Set();
  const viewerUserIds = new Set(Array.from(viewingRoom).map((ws) => ws.userId));

  for (const memberId of memberIds) {
    if (memberId === senderUserId) continue;
    if (viewerUserIds.has(memberId)) continue; // already seeing it live in this room

    try {
      await db.createNotification(memberId, room, 'message');
    } catch (e) { /* non-fatal */ }

    const otherSockets = userSockets.get(memberId);
    if (otherSockets && otherSockets.size > 0) {
      // Online elsewhere in the app: nudge the bell icon live, skip push.
      sendToUser(memberId, { type: 'notification', room });
      continue;
    }

    // Fully offline: try push.
    try {
      const subs = await db.getUserPushSubscriptions(memberId);
      for (const sub of subs) {
        const result = await push.sendPush(
          { endpoint: sub.endpoint, keys: sub.keys },
          { title: 'New message', body: `Someone posted in ${room}`, room }
        );
        if (result.gone) {
          await db.removePushSubscriptionByEndpoint(sub.endpoint);
        }
      }
    } catch (e) { /* push not configured or failed — non-fatal */ }
  }
}

function joinRoom(room, ws) {
  addToMap(rooms, room, ws);
  ws._room = room;
}

function leaveRoom(ws) {
  if (ws._room) removeFromMap(rooms, ws._room, ws);
  ws._room = null;
}

// ---- room membership / admin controls ----
// (Placed here, not with the other REST routes above, because they need
// direct access to the live `rooms` map to disconnect a just-kicked user.)

app.get('/api/rooms/:room/members', auth.requireAuth, async (req, res) => {
  const room = req.params.room;
  const isMember = await db.isRoomMember(req.userId, room);
  if (!isMember) return res.status(403).json({ error: 'You are not a member of this room.' });
  const members = await db.getRoomMembersWithInfo(room);
  res.json({ members });
});

app.post('/api/rooms/:room/role', auth.requireAuth, async (req, res) => {
  const room = req.params.room;
  const { targetUserId, role } = req.body || {};
  if (!targetUserId || !['member', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'targetUserId and role ("member" or "admin") are required.' });
  }
  const requester = await db.getMembership(req.userId, room);
  if (!requester || requester.role !== 'owner') {
    return res.status(403).json({ error: 'Only the room owner can change roles.' });
  }
  const target = await db.getMembership(targetUserId, room);
  if (!target) return res.status(404).json({ error: 'That user is not a member of this room.' });
  if (target.role === 'owner') return res.status(400).json({ error: "The owner's role cannot be changed." });
  await db.setMemberRole(room, targetUserId, role);
  res.json({ ok: true });
});

app.post('/api/rooms/:room/mute', auth.requireAuth, async (req, res) => {
  const room = req.params.room;
  const { targetUserId, muted } = req.body || {};
  if (!targetUserId || typeof muted !== 'boolean') {
    return res.status(400).json({ error: 'targetUserId and muted (boolean) are required.' });
  }
  const requester = await db.getMembership(req.userId, room);
  if (!requester || (requester.role !== 'owner' && requester.role !== 'admin')) {
    return res.status(403).json({ error: 'Only room owners/admins can mute members.' });
  }
  const target = await db.getMembership(targetUserId, room);
  if (!target) return res.status(404).json({ error: 'That user is not a member of this room.' });
  if (target.role === 'owner') return res.status(403).json({ error: 'The room owner cannot be muted.' });
  await db.setMemberMuted(room, targetUserId, muted);
  res.json({ ok: true, muted });
});

app.post('/api/rooms/:room/kick', auth.requireAuth, async (req, res) => {
  const room = req.params.room;
  const { targetUserId } = req.body || {};
  if (!targetUserId) return res.status(400).json({ error: 'targetUserId is required.' });
  const requester = await db.getMembership(req.userId, room);
  if (!requester || (requester.role !== 'owner' && requester.role !== 'admin')) {
    return res.status(403).json({ error: 'Only room owners/admins can remove members.' });
  }
  const target = await db.getMembership(targetUserId, room);
  if (!target) return res.status(404).json({ error: 'That user is not a member of this room.' });
  if (target.role === 'owner') return res.status(403).json({ error: 'The room owner cannot be removed.' });
  if (requester.role === 'admin' && target.role === 'admin') {
    return res.status(403).json({ error: 'Admins cannot remove other admins — only the owner can.' });
  }

  await db.removeMembership(room, targetUserId);

  // Force them out of the live room if they're connected right now.
  const set = rooms.get(room);
  if (set) {
    for (const client of set) {
      if (client.userId === targetUserId) {
        safeSend(client, { type: 'kicked', room });
        leaveRoom(client);
      }
    }
  }
  res.json({ ok: true });
});

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.userId = null;
  ws.username = null;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', async (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch (e) { return; }

    // ---- authenticate this socket ----
    if (msg.type === 'auth') {
      try {
        const decoded = auth.verifyToken(msg.token);
        ws.userId = decoded.sub;
        ws.username = decoded.username;
        addToMap(userSockets, ws.userId, ws);
        safeSend(ws, { type: 'authed', username: ws.username, userId: ws.userId });
      } catch (e) {
        safeSend(ws, { type: 'error', message: 'Invalid or expired session — please log in again.' });
        ws.close();
      }
      return;
    }

    if (!ws.userId) {
      safeSend(ws, { type: 'error', message: 'Not authenticated.' });
      return;
    }

    // ---- leave the room this socket is currently in, without disconnecting
    //      (keeps the socket alive so it still receives bell/push-relevant events) ----
    if (msg.type === 'leave') {
      leaveRoom(ws);
      return;
    }

    // ---- join a room (a socket is only ever "in" one room at a time) ----
    if (msg.type === 'join') {
      const room = String(msg.room || '').slice(0, MAX_ROOM_LEN);
      if (!room) return;
      leaveRoom(ws);
      joinRoom(room, ws);
      try {
        await db.upsertRoomMembership(ws.userId, room);
      } catch (e) { /* non-fatal */ }

      try {
        const docs = await db.getRoomMessages(room);
        const history = [];
        for (const doc of docs) {
          try {
            history.push(decryptAtRest({ iv: doc.iv, ct: doc.ct, tag: doc.tag }));
          } catch (e) { /* corrupted row or old key — skip */ }
        }
        safeSend(ws, { type: 'history', messages: history });
      } catch (e) {
        safeSend(ws, { type: 'error', message: 'Could not load message history.' });
      }
      return;
    }

    // ---- ephemeral typing indicator (not persisted, not encrypted — pure presence signal) ----
    if (msg.type === 'typing') {
      const room = ws._room;
      if (!room) return;
      broadcastToRoom(room, { type: 'typing', from: ws.userId, username: ws.username }, ws);
      return;
    }

    // ---- a chat message: text, poll, vote, or file-metadata (all opaque ciphertext to the server) ----
    if (msg.type === 'message') {
      const room = ws._room;
      if (!room) {
        safeSend(ws, { type: 'error', message: 'Join a room before sending messages.' });
        return;
      }

      try {
        const membership = await db.getMembership(ws.userId, room);
        if (membership && membership.muted) {
          safeSend(ws, { type: 'error', message: 'You are muted in this room and cannot send messages.' });
          return;
        }
      } catch (e) { /* if this check fails, fail open rather than blocking legitimate messages */ }

      const iv = typeof msg.iv === 'string' ? msg.iv.slice(0, MAX_MESSAGE_FIELD_LEN) : null;
      const ct = typeof msg.ct === 'string' ? msg.ct.slice(0, MAX_MESSAGE_FIELD_LEN) : null;
      const ts = Number.isFinite(msg.ts) ? msg.ts : Date.now();
      if (!iv || !ct) return;

      // 'from' is stamped server-side from the authenticated session —
      // never trusted from the client — so nobody can spoof another user.
      const payload = { iv, ct, ts, from: ws.userId };

      let blob;
      try {
        blob = encryptAtRest(payload);
      } catch (e) {
        safeSend(ws, { type: 'error', message: 'Server encryption is misconfigured: ' + e.message });
        return;
      }

      try {
        await db.insertMessage(room, ts, ws.userId, blob);
      } catch (e) {
        safeSend(ws, { type: 'error', message: 'Could not save your message. Please retry.' });
        return;
      }

      broadcastToRoom(room, { type: 'message', ...payload }, ws);
      notifyRoomMembers(room, ws.userId); // fire-and-forget
    }
  });

  ws.on('close', () => {
    leaveRoom(ws);
    if (ws.userId) removeFromMap(userSockets, ws.userId, ws);
  });
});

// Drop dead connections (e.g. laptop went to sleep) so rooms/userSockets don't leak.
const heartbeat = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      leaveRoom(ws);
      if (ws.userId) removeFromMap(userSockets, ws.userId, ws);
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);
wss.on('close', () => clearInterval(heartbeat));

db.connectDB()
  .then(() => {
    server.listen(PORT, () => console.log(`Secure chat server listening on http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('Startup failed:', err.message);
    process.exit(1);
  });
