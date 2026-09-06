const { MongoClient, ObjectId } = require('mongodb');

let client = null;
let db = null;

async function connectDB() {
  const uri = process.env.MONGO_URI;
  if (!uri) {
    throw new Error('MONGO_URI is not set. Put your MongoDB connection string in .env.');
  }
  client = new MongoClient(uri);
  await client.connect();
  db = client.db(process.env.MONGO_DB_NAME || 'secure_chat');

  await Promise.all([
    db.collection('messages').createIndex({ room: 1, ts: 1 }),
    db.collection('users').createIndex({ username: 1 }, { unique: true }),
    db.collection('room_memberships').createIndex({ userId: 1, room: 1 }, { unique: true }),
    db.collection('room_memberships').createIndex({ userId: 1, lastJoinedAt: -1 }),
    db.collection('notifications').createIndex({ userId: 1, read: 1, ts: -1 }),
    db.collection('push_subscriptions').createIndex({ endpoint: 1 }, { unique: true }),
    db.collection('push_subscriptions').createIndex({ userId: 1 }),
  ]);

  console.log('Connected to MongoDB.');
  return db;
}

function getDB() {
  if (!db) throw new Error('Database not connected yet.');
  return db;
}

async function closeDB() {
  if (client) await client.close();
}

// ---------------- messages (at-rest encrypted envelopes) ----------------

async function insertMessage(room, ts, userId, encryptedBlob) {
  const doc = { room, ts, userId, ...encryptedBlob, createdAt: new Date() };
  await getDB().collection('messages').insertOne(doc);
}

async function getRoomMessages(room, limit = 1000) {
  return getDB().collection('messages').find({ room }).sort({ ts: 1 }).limit(limit).toArray();
}

// ---------------- users ----------------

async function createUser(username, passwordHash) {
  const doc = { username, passwordHash, createdAt: new Date(), avatarEmoji: null, avatarColor: null };
  const result = await getDB().collection('users').insertOne(doc);
  return { _id: result.insertedId.toString(), username };
}

async function findUserByUsername(username) {
  return getDB().collection('users').findOne({ username });
}

async function findUserById(id) {
  return getDB().collection('users').findOne({ _id: new ObjectId(id) });
}

async function updateUserProfile(userId, { avatarEmoji, avatarColor }) {
  await getDB()
    .collection('users')
    .updateOne({ _id: new ObjectId(userId) }, { $set: { avatarEmoji, avatarColor } });
}

async function findUsersByIds(userIds) {
  const objectIds = [...new Set(userIds)].map((id) => new ObjectId(id));
  const docs = await getDB().collection('users').find({ _id: { $in: objectIds } }).toArray();
  const byId = new Map();
  for (const d of docs) byId.set(d._id.toString(), d);
  return byId;
}

// ---------------- room membership (per account) ----------------

async function upsertRoomMembership(userId, room) {
  const existingAnyOwner = await getDB().collection('room_memberships').findOne({ room, role: 'owner' });
  const role = existingAnyOwner ? 'member' : 'owner'; // first person to ever join a room owns it
  await getDB().collection('room_memberships').updateOne(
    { userId, room },
    {
      $set: { userId, room, lastJoinedAt: new Date() },
      $setOnInsert: { joinedAt: new Date(), role, muted: false },
    },
    { upsert: true }
  );
}

async function getUserRooms(userId) {
  return getDB().collection('room_memberships').find({ userId }).sort({ lastJoinedAt: -1 }).toArray();
}

async function getRoomMemberIds(room) {
  const docs = await getDB().collection('room_memberships').find({ room }).project({ userId: 1 }).toArray();
  return docs.map((d) => d.userId);
}

async function isRoomMember(userId, room) {
  const doc = await getDB().collection('room_memberships').findOne({ userId, room });
  return !!doc;
}

async function getMembership(userId, room) {
  return getDB().collection('room_memberships').findOne({ userId, room });
}

async function getRoomMembersWithInfo(room) {
  const memberships = await getDB().collection('room_memberships').find({ room }).toArray();
  const usersById = await findUsersByIds(memberships.map((m) => m.userId));
  return memberships.map((m) => {
    const user = usersById.get(m.userId);
    return {
      userId: m.userId,
      username: user ? user.username : 'unknown',
      avatarEmoji: user ? user.avatarEmoji : null,
      avatarColor: user ? user.avatarColor : null,
      role: m.role || 'member',
      muted: !!m.muted,
      joinedAt: m.joinedAt,
    };
  });
}

async function setMemberRole(room, targetUserId, role) {
  await getDB().collection('room_memberships').updateOne({ room, userId: targetUserId }, { $set: { role } });
}

async function setMemberMuted(room, targetUserId, muted) {
  await getDB().collection('room_memberships').updateOne({ room, userId: targetUserId }, { $set: { muted } });
}

async function removeMembership(room, targetUserId) {
  await getDB().collection('room_memberships').deleteOne({ room, userId: targetUserId });
}

// ---------------- notifications ----------------

async function createNotification(userId, room, kind) {
  await getDB().collection('notifications').insertOne({ userId, room, kind, ts: new Date(), read: false });
}

async function getUnreadNotifications(userId) {
  return getDB().collection('notifications').find({ userId, read: false }).sort({ ts: -1 }).limit(100).toArray();
}

async function markNotificationsRead(userId, ids) {
  const objectIds = ids.map((id) => new ObjectId(id));
  await getDB()
    .collection('notifications')
    .updateMany({ userId, _id: { $in: objectIds } }, { $set: { read: true } });
}

// ---------------- push subscriptions ----------------

async function savePushSubscription(userId, subscription) {
  await getDB().collection('push_subscriptions').updateOne(
    { endpoint: subscription.endpoint },
    { $set: { userId, endpoint: subscription.endpoint, keys: subscription.keys, updatedAt: new Date() } },
    { upsert: true }
  );
}

async function removePushSubscriptionByEndpoint(endpoint) {
  await getDB().collection('push_subscriptions').deleteOne({ endpoint });
}

async function getUserPushSubscriptions(userId) {
  return getDB().collection('push_subscriptions').find({ userId }).toArray();
}

module.exports = {
  connectDB,
  getDB,
  closeDB,
  insertMessage,
  getRoomMessages,
  createUser,
  findUserByUsername,
  findUserById,
  updateUserProfile,
  findUsersByIds,
  upsertRoomMembership,
  getUserRooms,
  getRoomMemberIds,
  isRoomMember,
  getMembership,
  getRoomMembersWithInfo,
  setMemberRole,
  setMemberMuted,
  removeMembership,
  createNotification,
  getUnreadNotifications,
  markNotificationsRead,
  savePushSubscription,
  removePushSubscriptionByEndpoint,
  getUserPushSubscriptions,
};
