'use strict';

/**
 * ciavault — layered-crypto.js
 *
 * Three-layer encryption pipeline:
 *
 *   Layer 1 — AES-256-GCM
 *     scrypt-derived key (N=16384,r=8,p=1), random salt + IV, auth tag
 *     Frame: [CVL1(4)] [salt(32)] [iv(16)] [tag(16)] [ciphertext]
 *
 *   Layer 2 — SHA-256 integrity frame
 *     Binds L1 ciphertext length + hash so no bytes are ever lost or silently
 *     flipped before L1 decryption is attempted.
 *     Frame: [CVL2(4)] [len(4)] [L1-frame] [sha256(32)]
 *
 *   Layer 3 — ChaCha20-Poly1305 master wrapper
 *     Independent scrypt-derived key (different salt → different key).
 *     Frame: [CVL3(4)] [salt(32)] [nonce(12)] [tag(16)] [encrypted-L2-frame]
 *
 * All lengths are uint32LE. All crypto is Node.js built-in — zero native deps.
 */

const crypto = require('crypto');

// ─── Constants ────────────────────────────────────────────────────────────────

const MAGIC_L1     = Buffer.from('CVL1');
const MAGIC_L2     = Buffer.from('CVL2');
const MAGIC_L3     = Buffer.from('CVL3');
const SALT_LEN     = 32;
const IV_GCM_LEN   = 16;
const TAG_GCM_LEN  = 16;
const NONCE_CC_LEN = 12;
const TAG_CC_LEN   = 16;
const SHA256_LEN   = 32;
const KEY_LEN      = 32;

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

// ─── KDF ─────────────────────────────────────────────────────────────────────

/**
 * scrypt KDF. Password is NFC-normalised so Unicode chars in the generated
 * passphrase always produce the same key regardless of host platform.
 */
function deriveKey(password, salt) {
  const pwBuf = Buffer.from(password.normalize('NFC'), 'utf8');
  return new Promise((resolve, reject) => {
    crypto.scrypt(pwBuf, salt, KEY_LEN, SCRYPT_PARAMS, (err, key) =>
      err ? reject(err) : resolve(key)
    );
  });
}

// ─── Layer 1 — AES-256-GCM ───────────────────────────────────────────────────

async function encryptL1(plaintext, password) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv   = crypto.randomBytes(IV_GCM_LEN);
  const key  = await deriveKey(password, salt);

  const cipher     = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag        = cipher.getAuthTag();

  return Buffer.concat([MAGIC_L1, salt, iv, tag, ciphertext]);
}

async function decryptL1(frame, password) {
  if (frame.length < 4 + SALT_LEN + IV_GCM_LEN + TAG_GCM_LEN)
    throw new Error('[L1] Frame too short');

  let off = 0;
  const magic = frame.slice(off, off + 4); off += 4;
  if (!magic.equals(MAGIC_L1)) throw new Error('[L1] Magic mismatch');

  const salt       = frame.slice(off, off + SALT_LEN);    off += SALT_LEN;
  const iv         = frame.slice(off, off + IV_GCM_LEN);  off += IV_GCM_LEN;
  const tag        = frame.slice(off, off + TAG_GCM_LEN); off += TAG_GCM_LEN;
  const ciphertext = frame.slice(off);

  const key      = await deriveKey(password, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('[L1] AES-256-GCM authentication failed — wrong password or corrupted data');
  }
}

// ─── Layer 2 — SHA-256 integrity frame ───────────────────────────────────────

function wrapL2(l1Frame) {
  const lenBuf = Buffer.allocUnsafe(4);
  lenBuf.writeUInt32LE(l1Frame.length, 0);
  const hash = crypto.createHash('sha256').update(l1Frame).digest();
  return Buffer.concat([MAGIC_L2, lenBuf, l1Frame, hash]);
}

function unwrapL2(frame) {
  if (frame.length < 4 + 4 + SHA256_LEN) throw new Error('[L2] Frame too short');

  let off = 0;
  const magic = frame.slice(off, off + 4); off += 4;
  if (!magic.equals(MAGIC_L2)) throw new Error('[L2] Magic mismatch');

  const l1Len  = frame.readUInt32LE(off); off += 4;
  const l1Frame = frame.slice(off, off + l1Len); off += l1Len;
  const storedHash = frame.slice(off, off + SHA256_LEN);

  if (l1Frame.length !== l1Len)
    throw new Error('[L2] Payload length mismatch — data is truncated or corrupted');

  const computedHash = crypto.createHash('sha256').update(l1Frame).digest();
  if (!crypto.timingSafeEqual(storedHash, computedHash))
    throw new Error('[L2] SHA-256 integrity check failed — ciphertext has been tampered with');

  return l1Frame;
}

// ─── Layer 3 — ChaCha20-Poly1305 ─────────────────────────────────────────────

async function encryptL3(l2Frame, password) {
  const salt  = crypto.randomBytes(SALT_LEN);
  const nonce = crypto.randomBytes(NONCE_CC_LEN);
  const key   = await deriveKey(password, salt);

  const cipher     = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: TAG_CC_LEN });
  const ciphertext = Buffer.concat([cipher.update(l2Frame), cipher.final()]);
  const tag        = cipher.getAuthTag();

  return Buffer.concat([MAGIC_L3, salt, nonce, tag, ciphertext]);
}

async function decryptL3(frame, password) {
  if (frame.length < 4 + SALT_LEN + NONCE_CC_LEN + TAG_CC_LEN)
    throw new Error('[L3] Frame too short');

  let off = 0;
  const magic = frame.slice(off, off + 4); off += 4;
  if (!magic.equals(MAGIC_L3)) throw new Error('[L3] Magic mismatch');

  const salt       = frame.slice(off, off + SALT_LEN);      off += SALT_LEN;
  const nonce      = frame.slice(off, off + NONCE_CC_LEN);  off += NONCE_CC_LEN;
  const tag        = frame.slice(off, off + TAG_CC_LEN);    off += TAG_CC_LEN;
  const ciphertext = frame.slice(off);

  const key      = await deriveKey(password, salt);
  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: TAG_CC_LEN });
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('[L3] ChaCha20-Poly1305 authentication failed — wrong password or corrupted data');
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Encrypt plaintext through all three layers.
 * @param {Buffer|string} plaintext
 * @param {string}        password
 * @returns {Promise<Buffer>}
 */
async function encrypt(plaintext, password) {
  if (typeof plaintext === 'string') plaintext = Buffer.from(plaintext, 'utf8');
  if (!Buffer.isBuffer(plaintext))   throw new TypeError('plaintext must be a Buffer or string');
  if (!password)                     throw new TypeError('password is required');

  const l1 = await encryptL1(plaintext, password);
  const l2 = wrapL2(l1);
  return encryptL3(l2, password);
}

/**
 * Decrypt a three-layer ciphertext.
 * @param {Buffer} ciphertext
 * @param {string} password
 * @returns {Promise<Buffer>}
 */
async function decrypt(ciphertext, password) {
  if (!Buffer.isBuffer(ciphertext)) throw new TypeError('ciphertext must be a Buffer');
  if (!password)                    throw new TypeError('password is required');

  const l2 = await decryptL3(ciphertext, password);
  const l1 = unwrapL2(l2);
  return decryptL1(l1, password);
}

module.exports = { encrypt, decrypt };
