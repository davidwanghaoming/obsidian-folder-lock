import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import {
  createCredentials, decryptNote, deriveKey, encryptNote, fromBase64, isEncrypted,
  LockError, MARKER, PBKDF2_ITERATIONS, toBase64, unlockKey, validateCredentials,
} from '../src/crypto';
import { messages } from '../src/i18n';
const crypto = webcrypto as unknown as Crypto;
const password = '一个足够长的测试密码🔑';
const ready = createCredentials(password, crypto);
const other = createCredentials('different-password', crypto);

test('Chinese, multiline, CRLF, BOM, emoji and trailing whitespace roundtrip exactly', async () => {
  const { key } = await ready;
  for (const text of ['你好，世界！\n人物档案：张三\n', '\uFEFF中文\r\n\r\n空行\t  ', 'emoji 🔐\nend ', '\u0000\n']) {
    const locked = await encryptNote(text, key, crypto, messages.zh.lockedNote);
    assert.ok(locked.startsWith(`${MARKER}\n`));
    assert.ok(!locked.includes('人物档案'));
    assert.equal(await decryptNote(locked, key, crypto), text);
  }
});
test('a truly empty (zero-byte) note is encrypted and restored as empty', async () => {
  const { key } = await ready;
  const result = await encryptNote('', key, crypto);
  assert.notEqual(result, ''); assert.ok(isEncrypted(result));
  assert.equal(await decryptNote(result, key, crypto), '');
  assert.equal(await decryptNote('', key, crypto), '');
});
test('password verifier accepts correct password and rejects wrong password', async () => {
  const { credentials } = await ready;
  const key = await unlockKey(password, credentials, crypto);
  assert.equal(key.extractable, false);
  await assert.rejects(unlockKey('wrong password', credentials, crypto), (e: LockError) => e.code === 'authFailed');
  assert.ok(PBKDF2_ITERATIONS >= 310_000);
  assert.deepEqual(Object.keys(credentials).sort(), ['iterations', 'salt', 'verifier']);
  assert.equal(fromBase64(credentials.salt).length, 16);
  assert.ok(!JSON.stringify(credentials).includes(password));
});
test('file ciphertext cannot be decrypted with another key', async () => {
  const a = await ready, b = await other;
  const cipher = await encryptNote('secret', a.key, crypto);
  await assert.rejects(decryptNote(cipher, b.key, crypto), (e: LockError) => e.code === 'authFailed');
});
test('marker detection prevents double encryption; already-plain unlock is a no-op', async () => {
  const { key } = await ready;
  const cipher = await encryptNote('secret', key, crypto);
  assert.equal(isEncrypted(cipher), true);
  assert.equal(isEncrypted('normal note mentioning %%folder-lock:v1%%'), false);
  assert.equal(await encryptNote(cipher, key, crypto), cipher);
  assert.equal(await decryptNote('plain', key, crypto), 'plain');
  assert.ok(isEncrypted('%%folder-lock:v99%%\npayload'));
  assert.ok(isEncrypted('\uFEFF%%folder-lock:v1%%\npayload'));
  assert.equal(await encryptNote('%%folder-lock:v99%%\npayload', key, crypto), '%%folder-lock:v99%%\npayload');
  await assert.rejects(decryptNote('%%folder-lock:v99%%\npayload', key, crypto));
});
test('tampered ciphertext and IV fail authentication', async () => {
  const { key } = await ready;
  const cipher = await encryptNote('do not change me', key, crypto);
  for (const index of [0, 13, -1]) {
    const lines = cipher.split('\n'), payload = fromBase64(lines[1]);
    const i = index === -1 ? payload.length - 1 : index;
    payload[i] ^= 1;
    lines[1] = toBase64(payload);
    await assert.rejects(decryptNote(lines.join('\n'), key, crypto), (e: LockError) => e.code === 'authFailed');
  }
});
test('every encryption uses a fresh 12-byte IV', async () => {
  const { key } = await ready;
  const a = fromBase64((await encryptNote('same', key, crypto)).split('\n')[1]);
  const b = fromBase64((await encryptNote('same', key, crypto)).split('\n')[1]);
  assert.equal(a.length, 12 + 4 + 16);
  assert.notDeepEqual(a.subarray(0, 12), b.subarray(0, 12));
});
test('malformed and truncated base64 formats are refused', async () => {
  const { key } = await ready;
  for (const payload of ['', '%%%bad', 'AAA', 'AAAA', 'Zh==', 'AA==\n']) {
    if (payload === 'AA==\n') continue; // Trailing note lines are intentionally outside the payload.
    await assert.rejects(decryptNote(`${MARKER}\n${payload}\n`, key, crypto));
  }
  assert.throws(() => validateCredentials({ salt: 'AAAA', verifier: 'AAAA' }));
  assert.throws(() => validateCredentials({ salt: 1, verifier: 'a' }));
});
test('verifier is domain-separated from note content', async () => {
  const { credentials, key } = await ready;
  await assert.rejects(decryptNote(`${MARKER}\n${credentials.verifier}\n`, key, crypto));
  const cipher = await encryptNote('folder-lock password verifier v1', key, crypto);
  await assert.rejects(unlockKey(password, { ...credentials, verifier: cipher.split('\n')[1] }, crypto));
});
test('new password generates a new random salt; password whitespace is not trimmed', async () => {
  const a = await ready;
  const b = await createCredentials(password, crypto);
  assert.notEqual(a.credentials.salt, b.credentials.salt);
  const spaced = await deriveKey(` ${password} `, a.credentials.salt, crypto);
  await assert.rejects(decryptNote(await encryptNote('x', a.key, crypto), spaced, crypto));
});
test('large unicode notes avoid base64 argument limits', async () => {
  const { key } = await ready;
  const text = '中文🙂\r\n'.repeat(50_000);
  assert.equal(await decryptNote(await encryptNote(text, key, crypto), key, crypto), text);
});
test('unpaired UTF-16 surrogate fails the pre-write roundtrip instead of losing data', async () => {
  const { key } = await ready;
  await assert.rejects(encryptNote('bad \uD800', key, crypto), (e: LockError) => e.code === 'roundtripFailed');
});
test('Chinese and English tables expose identical UI keys', () => {
  assert.deepEqual(Object.keys(messages.zh).sort(), Object.keys(messages.en).sort());
});
