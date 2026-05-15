'use strict';

const crypto = require('crypto');

const SCRYPT_SALT_LEN = 32;
const IV_LEN          = 16;
const TAG_LEN         = 16;
const KEY_LEN         = 32;

const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };

/**
 * Encrypt a buffer with AES-256-GCM using a passphrase.
 * Output format: [salt (32)] [iv (16)] [tag (16)] [ciphertext]
 */
async function encrypt(plaintext, passphrase) {
  const salt = crypto.randomBytes(SCRYPT_SALT_LEN);
  const iv   = crypto.randomBytes(IV_LEN);
  const key  = await deriveKey(passphrase, salt);

  const cipher    = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag       = cipher.getAuthTag();

  return Buffer.concat([salt, iv, tag, encrypted]);
}

/**
 * Decrypt a buffer with AES-256-GCM using a passphrase.
 */
async function decrypt(ciphertext, passphrase) {
  if (ciphertext.length < SCRYPT_SALT_LEN + IV_LEN + TAG_LEN)
    throw new Error('Invalid ciphertext: too short');

  let offset = 0;
  const salt = ciphertext.slice(offset, offset + SCRYPT_SALT_LEN); offset += SCRYPT_SALT_LEN;
  const iv   = ciphertext.slice(offset, offset + IV_LEN);          offset += IV_LEN;
  const tag  = ciphertext.slice(offset, offset + TAG_LEN);         offset += TAG_LEN;
  const data = ciphertext.slice(offset);

  const key     = await deriveKey(passphrase, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  try {
    return Buffer.concat([decipher.update(data), decipher.final()]);
  } catch {
    throw new Error('Decryption failed: wrong passphrase or corrupted data');
  }
}

function deriveKey(passphrase, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(passphrase, salt, KEY_LEN, SCRYPT_PARAMS, (err, key) =>
      err ? reject(err) : resolve(key)
    );
  });
}

module.exports = { encrypt, decrypt };
