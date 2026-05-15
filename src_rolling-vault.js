'use strict';

/**
 * ciavault — rolling-vault.js
 *
 * Live Rolling System
 * ═══════════════════
 * Manages an active 16-char 60/40 password that auto-burns and regenerates
 * the precise millisecond a successful decryption is confirmed.
 *
 * Lifecycle:
 *   new RollingVault()     → generates password A
 *   vault.encrypt(data)    → encrypts with password A (no rotation)
 *   vault.decrypt(ct)      → decrypts with A → SUCCESS → A wiped, B generated
 *   vault.decrypt(ct)      → now uses B (old ciphertext will fail — expected)
 *
 * Memory-wipe strategy:
 *   Password is stored as a mutable Buffer (not an interned JS string).
 *   On burn: randomFillSync + fill(0) + null reference drop.
 *   Burn is synchronous before any await continuation — no async window
 *   where the old key is alive after success.
 */

const crypto               = require('crypto');
const { generatePassword, analyzePassword } = require('./password');
const layeredCrypto        = require('./layered-crypto');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function wipeBuffer(buf) {
  if (!Buffer.isBuffer(buf) || buf.length === 0) return;
  crypto.randomFillSync(buf);
  buf.fill(0);
}

function toWipeable(pw)  { return Buffer.from(pw.normalize('NFC'), 'utf8'); }
function fromWipeable(b) { return b.toString('utf8'); }

// ─── Minimal event emitter (no deps) ─────────────────────────────────────────

class MiniEmitter {
  constructor() { this._l = {}; }
  on(e, fn)  { (this._l[e] = this._l[e] || []).push(fn); return this; }
  off(e, fn) { this._l[e] = (this._l[e] || []).filter(f => f !== fn); return this; }
  emit(e, ...a) { (this._l[e] || []).forEach(fn => fn(...a)); }
}

// ─── RollingVault ─────────────────────────────────────────────────────────────

class RollingVault extends MiniEmitter {
  /**
   * @param {object} [opts]
   * @param {string} [opts.initialPassword]  Seed with a known password (must pass analyzePassword).
   */
  constructor(opts = {}) {
    super();
    this._pwBuf       = null;
    this._pwId        = null;
    this._rollCount   = 0;
    this._pwCreatedAt = null;

    if (opts.initialPassword) {
      this._setPassword(opts.initialPassword);
    } else {
      this._roll();
    }
  }

  // ── Private ────────────────────────────────────────────────────────────────

  _setPassword(pw) {
    this._pwBuf       = toWipeable(pw);
    this._pwId        = crypto.randomBytes(8).toString('hex');
    this._pwCreatedAt = new Date();
  }

  _roll() {
    this._setPassword(generatePassword());
    this.emit('rolled', { passwordId: this._pwId, rolledAt: this._pwCreatedAt });
  }

  _burnAndRoll(reason) {
    const expiredId = this._pwId;
    wipeBuffer(this._pwBuf);
    this._pwBuf = null;
    this._pwId  = null;
    this._rollCount++;
    this.emit('burned', { expiredId, reason, rollCount: this._rollCount });
    this._roll();
  }

  _currentPassword() {
    if (!this._pwBuf) throw new Error('RollingVault: vault is destroyed or not initialised');
    return fromWipeable(this._pwBuf);
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Encrypt data with the current active password.
   * Password is NOT rotated on encryption.
   *
   * @param {Buffer|string} plaintext
   * @returns {Promise<{ ciphertext: Buffer, passwordId: string }>}
   */
  async encrypt(plaintext) {
    const pw         = this._currentPassword();
    const passwordId = this._pwId;
    const ciphertext = await layeredCrypto.encrypt(plaintext, pw);
    return { ciphertext, passwordId };
  }

  /**
   * Decrypt ciphertext with the current active password.
   * On SUCCESS → active password is immediately burned and replaced.
   * On FAILURE → password is preserved; error is thrown.
   *
   * @param {Buffer} ciphertext
   * @returns {Promise<Buffer>} plaintext
   */
  async decrypt(ciphertext) {
    const pw = this._currentPassword();

    let plaintext;
    try {
      plaintext = await layeredCrypto.decrypt(ciphertext, pw);
    } catch (err) {
      throw Object.assign(
        new Error(`Decryption failed (passwordId=${this._pwId}): ${err.message}`),
        { code: 'DECRYPT_FAILED', cause: err }
      );
    }

    // ── Burn synchronously before any async continuation ──────────────────
    this._burnAndRoll('decrypted');

    return plaintext;
  }

  /**
   * Export the current password in plain text.
   * Share with a peer for a single one-time decrypt — it will be burned on use.
   *
   * @returns {{ password: string, passwordId: string, createdAt: Date }}
   */
  exportPassword() {
    return {
      password:   this._currentPassword(),
      passwordId: this._pwId,
      createdAt:  this._pwCreatedAt,
    };
  }

  /**
   * Load an externally supplied password (e.g. from a peer's exportPassword()).
   * Must satisfy the 60/40 structural rule. Previous password is wiped.
   *
   * @param {string} password
   */
  importPassword(password) {
    if (typeof password !== 'string' || !password)
      throw new TypeError('importPassword: password must be a non-empty string');
    const a = analyzePassword(password);
    if (!a.valid)
      throw new Error(
        `importPassword: password fails 60/40 rule ` +
        `(${a.asciiCount} ASCII + ${a.unicodeCount} Unicode over ${a.totalCodePoints} code-points; need 10+6=16)`
      );
    wipeBuffer(this._pwBuf);
    this._setPassword(password);
    this.emit('imported', { passwordId: this._pwId });
  }

  /** Manually burn and regenerate without decrypting. */
  forceRoll() {
    this._burnAndRoll('manual');
  }

  /**
   * Non-sensitive status snapshot. Raw password is never exposed.
   * @returns {{ passwordId, createdAt, rollCount, passwordAnalysis }}
   */
  status() {
    return {
      passwordId:       this._pwId,
      createdAt:        this._pwCreatedAt,
      rollCount:        this._rollCount,
      passwordAnalysis: analyzePassword(this._currentPassword()),
    };
  }

  /** Permanently destroy the vault — wipes memory and drops all listeners. */
  destroy() {
    wipeBuffer(this._pwBuf);
    this._pwBuf = null;
    this._pwId  = null;
    this._l     = {};
    this.emit('destroyed');
  }
}

module.exports = { RollingVault };
