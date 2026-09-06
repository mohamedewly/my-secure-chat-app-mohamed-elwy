process.env.S3_BUCKET = 'test-bucket';
process.env.S3_ACCESS_KEY_ID = 'AKIAFAKEFAKEFAKEFAKE';
process.env.S3_SECRET_ACCESS_KEY = 'fakeSecretKeyForLocalSigningTestOnly1234567890';
process.env.S3_REGION = 'us-east-1';

const { getUploadUrl, getDownloadUrl, buildObjectKey, sanitizeKeyPart } = require('./storage');

async function main() {
  const key = buildObjectKey('midnight-otter-42', 'my photo!!.png');
  if (!key.startsWith('rooms/midnight-otter-42/')) throw new Error('FAIL: key should be namespaced by room');
  if (!key.endsWith('_my_photo__.png')) throw new Error('FAIL: unsafe filename characters should be sanitized, got: ' + key);
  console.log('buildObjectKey: OK ->', key);

  if (sanitizeKeyPart('../../etc/passwd') === '../../etc/passwd') {
    throw new Error('FAIL: path traversal characters should be stripped');
  }
  console.log('sanitizeKeyPart blocks path traversal: OK');

  const uploadUrl = await getUploadUrl(key, 'image/png');
  if (!uploadUrl.startsWith('https://')) throw new Error('FAIL: expected a signed https URL');
  if (!uploadUrl.includes('test-bucket')) throw new Error('FAIL: bucket name should appear in the signed URL');
  if (!uploadUrl.includes('X-Amz-Signature')) throw new Error('FAIL: expected a SigV4 signature in the URL');
  console.log('getUploadUrl produces a signed URL: OK');
  console.log('  ->', uploadUrl.slice(0, 100) + '...');

  const downloadUrl = await getDownloadUrl(key);
  if (!downloadUrl.includes('X-Amz-Signature')) throw new Error('FAIL: expected a SigV4 signature in the download URL');
  console.log('getDownloadUrl produces a signed URL: OK');

  // --- common .env mistakes should be handled gracefully ---
  const savedEndpoint = process.env.S3_ENDPOINT;

  process.env.S3_ENDPOINT = 's3.us-west-004.backblazeb2.com'; // missing https://
  let gotClearError = false;
  try { await getUploadUrl(key, 'image/png'); }
  catch (e) { gotClearError = /must start with/.test(e.message); }
  if (!gotClearError) throw new Error('FAIL: missing-scheme endpoint should produce a clear, specific error');
  console.log('Missing "https://" in S3_ENDPOINT produces a clear error: OK');

  process.env.S3_ENDPOINT = '"https://s3.us-west-004.backblazeb2.com"'; // stray wrapping quotes
  const quotedUrl = await getUploadUrl(key, 'image/png');
  if (quotedUrl.includes('%22') || quotedUrl.includes('"')) throw new Error('FAIL: stray quotes in S3_ENDPOINT should be stripped');
  console.log('Stray quotes in S3_ENDPOINT are stripped automatically: OK');

  process.env.S3_ENDPOINT = 'https://s3.us-west-004.backblazeb2.com/'; // trailing slash
  const slashUrl = await getUploadUrl(key, 'image/png');
  if (!slashUrl.startsWith('https://s3.us-west-004.backblazeb2.com/test-bucket/')) throw new Error('FAIL: trailing slash in S3_ENDPOINT should be handled, got: ' + slashUrl);
  console.log('Trailing slash in S3_ENDPOINT is handled automatically: OK');

  process.env.S3_ENDPOINT = savedEndpoint;

  console.log('\nAll storage self-tests passed (note: signing is tested locally; actual upload/download against a real bucket is not, since this sandbox has no network access to S3-compatible endpoints).');
}

main().catch((e) => { console.error('FAILED:', e); process.exit(1); });
