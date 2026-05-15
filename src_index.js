'use strict';

/**
 * ciavault — programmatic API (v2)
 *
 * Original steganography API (unchanged):
 *   hide(options)    → Promise<Buffer>
 *   reveal(options)  → Promise<{ filename, data }>
 *   info(options)    → Promise<object>
 *
 * New rolling-vault API:
 *   generatePassword()          → string          (16-char 60/40 password)
 *   analyzePassword(pw)         → object           (structural audit)
 *   encrypt(plaintext, pw)      → Promise<Buffer>  (3-layer: AES-GCM → SHA-256 → ChaCha20)
 *   decrypt(ciphertext, pw)     → Promise<Buffer>
 *   new RollingVault([opts])    → stateful vault that auto-burns on decrypt
 */

const fs               = require('fs');
const path             = require('path');
const lsb              = require('./methods/lsb');
const eof              = require('./methods/eof');
const passphraseCrypto = require('./crypto');
const utils            = require('./utils');
const { generatePassword, analyzePassword } = require('./password');
const layeredCrypto    = require('./layered-crypto');
const { RollingVault } = require('./rolling-vault');

// ─── Method registry ─────────────────────────────────────────────────────────

const METHODS = { lsb, eof };

function detectMethod(filePath) {
  return path.extname(filePath).toLowerCase() === '.png' ? 'lsb' : 'eof';
}

// ─── hide ─────────────────────────────────────────────────────────────────────

/**
 * Hide a secret file inside a carrier file.
 *
 * @param {object}        options
 * @param {string|Buffer} options.carrier
 * @param {string|Buffer} options.secret
 * @param {string}        [options.secretName]   required when secret is a Buffer
 * @param {string}        [options.method]        'lsb' | 'eof' | 'auto'  (default: 'auto')
 * @param {string}        [options.passphrase]    encrypt payload with AES-256-GCM
 * @returns {Promise<Buffer>}
 */
async function hide(options = {}) {
  const { carrier, secret, secretName, method = 'auto', passphrase } = options;

  if (!carrier) throw new Error('options.carrier is required');
  if (!secret)  throw new Error('options.secret is required');

  const carrierBuf   = Buffer.isBuffer(carrier) ? carrier : fs.readFileSync(carrier);
  const carrierName  = Buffer.isBuffer(carrier) ? 'carrier' : carrier;
  const secretBuf    = Buffer.isBuffer(secret)  ? secret  : fs.readFileSync(secret);
  const resolvedName = secretName || (Buffer.isBuffer(secret) ? 'secret' : path.basename(secret));

  let payload = utils.packPayload(resolvedName, secretBuf, !!passphrase);
  if (passphrase) payload = await passphraseCrypto.encrypt(payload, passphrase);

  const resolvedMethod = method === 'auto' ? detectMethod(carrierName) : method;
  const engine = METHODS[resolvedMethod];
  if (!engine) throw new Error(`Unknown method: ${resolvedMethod}. Use 'lsb', 'eof', or 'auto'`);

  return engine.hide(carrierBuf, payload);
}

// ─── reveal ───────────────────────────────────────────────────────────────────

/**
 * Reveal a secret file hidden inside a carrier file.
 *
 * @param {object}        options
 * @param {string|Buffer} options.carrier
 * @param {string}        [options.method]     'lsb' | 'eof' | 'auto'
 * @param {string}        [options.passphrase] required if payload was encrypted
 * @returns {Promise<{ filename: string, data: Buffer }>}
 */
async function reveal(options = {}) {
  const { carrier, method = 'auto', passphrase } = options;

  if (!carrier) throw new Error('options.carrier is required');

  const carrierBuf  = Buffer.isBuffer(carrier) ? carrier : fs.readFileSync(carrier);
  const carrierName = Buffer.isBuffer(carrier) ? 'carrier' : carrier;

  const resolvedMethod = method === 'auto' ? detectMethod(carrierName) : method;
  const engine = METHODS[resolvedMethod];
  if (!engine) throw new Error(`Unknown method: ${resolvedMethod}`);

  let rawPayload;
  if (resolvedMethod === 'eof') {
    const result = await engine.reveal(carrierBuf);
    rawPayload = result.payload;
  } else {
    rawPayload = await engine.reveal(carrierBuf);
  }

  let payloadBuf;
  try {
    const { MAGIC } = require('./utils');
    if (rawPayload.slice(0, MAGIC.length).equals(MAGIC)) {
      payloadBuf = rawPayload;
    } else if (passphrase) {
      payloadBuf = await passphraseCrypto.decrypt(rawPayload, passphrase);
    } else {
      throw new Error('Payload appears encrypted but no --passphrase was provided');
    }
  } catch (err) {
    if (err.message.includes('no --passphrase')) throw err;
    if (passphrase) {
      payloadBuf = await passphraseCrypto.decrypt(rawPayload, passphrase);
    } else {
      throw new Error('Payload appears encrypted but no --passphrase was provided');
    }
  }

  return utils.unpackPayload(payloadBuf);
}

// ─── info ─────────────────────────────────────────────────────────────────────

/**
 * Check whether a file contains a CIAVault payload (without decrypting).
 *
 * @param {object}        options
 * @param {string|Buffer} options.carrier
 * @param {string}        [options.method]
 * @returns {Promise<{ hasPayload: boolean, encrypted?: boolean, filename?: string, size?: number }>}
 */
async function info(options = {}) {
  try {
    const result = await reveal({ ...options, passphrase: undefined });
    return { hasPayload: true, encrypted: false, filename: result.filename, size: result.data.length };
  } catch (err) {
    if (err.message.includes('encrypted')) return { hasPayload: true, encrypted: true };
    return { hasPayload: false };
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  // ── Steganography (original, unchanged) ───────────────────────────────────
  hide,
  reveal,
  info,
  METHODS: Object.keys(METHODS),

  // ── Password generation ───────────────────────────────────────────────────
  /**
   * Generate a fresh 16-character 60/40 ASCII/Unicode password.
   * @returns {string}
   */
  generatePassword,

  /**
   * Audit a password string against the 60/40 structural rule.
   * @param {string} password
   * @returns {{ valid, asciiCount, unicodeCount, totalCodePoints }}
   */
  analyzePassword,

  // ── Three-layer stateless encryption ──────────────────────────────────────
  /**
   * Encrypt plaintext through AES-256-GCM → SHA-256 integrity → ChaCha20-Poly1305.
   * @param {Buffer|string} plaintext
   * @param {string}        password   — use generatePassword() to produce one
   * @returns {Promise<Buffer>}
   */
  encrypt: layeredCrypto.encrypt,

  /**
   * Decrypt a three-layer ciphertext produced by encrypt().
   * @param {Buffer} ciphertext
   * @param {string} password
   * @returns {Promise<Buffer>}
   */
  decrypt: layeredCrypto.decrypt,

  // ── Live Rolling Vault (stateful) ─────────────────────────────────────────
  /**
   * Stateful vault. Auto-burns its password on every successful decryption
   * and immediately generates a new one for the next cycle.
   *
   * Events: 'rolled', 'burned', 'imported', 'destroyed'
   *
   * @example
   *   const vault = new ciavault.RollingVault();
   *   const { ciphertext, passwordId } = await vault.encrypt(data);
   *   const plain = await vault.decrypt(ciphertext); // password rolls here
   */
  RollingVault,
};
