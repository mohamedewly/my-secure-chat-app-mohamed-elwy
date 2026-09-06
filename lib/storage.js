// Works with AWS S3 or any S3-compatible provider (Cloudflare R2,
// Backblaze B2, DigitalOcean Spaces, MinIO, etc) by setting S3_ENDPOINT.
//
// Files are uploaded directly from the browser to the bucket via a
// presigned URL — bytes never pass through this Node server. What gets
// uploaded is already end-to-end encrypted client-side (see public/index.html),
// so the bucket only ever holds ciphertext.

const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

function cleanEnvValue(v) {
  if (typeof v !== 'string') return v;
  let out = v.trim();
  // Defensively strip accidental wrapping quotes (a common .env copy/paste artifact).
  if ((out.startsWith('"') && out.endsWith('"')) || (out.startsWith("'") && out.endsWith("'"))) {
    out = out.slice(1, -1).trim();
  }
  return out;
}

function assertConfigured() {
  const required = ['S3_BUCKET', 'S3_ACCESS_KEY_ID', 'S3_SECRET_ACCESS_KEY', 'S3_REGION'];
  const missing = required.filter((k) => !process.env[k]);
  if (missing.length) {
    throw new Error('Missing S3 configuration in .env: ' + missing.join(', '));
  }
  const endpoint = cleanEnvValue(process.env.S3_ENDPOINT);
  if (endpoint) {
    if (!/^https?:\/\//i.test(endpoint)) {
      throw new Error(
        `S3_ENDPOINT must start with "https://" (or "http://"). ` +
        `Got: "${endpoint}". It should look like https://s3.us-west-004.backblazeb2.com ` +
        `or https://<account-id>.r2.cloudflarestorage.com — check .env for a missing scheme, ` +
        `a stray quote character, or an extra trailing slash.`
      );
    }
    try {
      new URL(endpoint);
    } catch (e) {
      throw new Error(`S3_ENDPOINT is not a valid URL: "${endpoint}". Check .env for typos or stray characters.`);
    }
  }
}

function getClient() {
  const config = {
    region: cleanEnvValue(process.env.S3_REGION),
    credentials: {
      accessKeyId: cleanEnvValue(process.env.S3_ACCESS_KEY_ID),
      secretAccessKey: cleanEnvValue(process.env.S3_SECRET_ACCESS_KEY),
    },
  };
  // Only set for non-AWS providers (R2, Spaces, MinIO, etc). Leave unset for real AWS S3.
  const endpoint = cleanEnvValue(process.env.S3_ENDPOINT);
  if (endpoint) {
    config.endpoint = endpoint.replace(/\/+$/, ''); // strip any trailing slash(es)
    config.forcePathStyle = true;
  }
  return new S3Client(config);
}

function sanitizeKeyPart(str) {
  return String(str).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 100);
}

function buildObjectKey(room, filename) {
  const id = require('crypto').randomUUID();
  return `rooms/${sanitizeKeyPart(room)}/${id}_${sanitizeKeyPart(filename)}`;
}

async function getUploadUrl(key, contentType, expiresInSeconds = 300) {
  assertConfigured();
  const client = getClient();
  const command = new PutObjectCommand({
    Bucket: cleanEnvValue(process.env.S3_BUCKET),
    Key: key,
    ContentType: contentType || 'application/octet-stream',
  });
  return getSignedUrl(client, command, { expiresIn: expiresInSeconds });
}

async function getDownloadUrl(key, expiresInSeconds = 300) {
  assertConfigured();
  const client = getClient();
  const command = new GetObjectCommand({ Bucket: cleanEnvValue(process.env.S3_BUCKET), Key: key });
  return getSignedUrl(client, command, { expiresIn: expiresInSeconds });
}

module.exports = { getUploadUrl, getDownloadUrl, buildObjectKey, sanitizeKeyPart };
