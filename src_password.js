'use strict';

/**
 * ciavault — password.js
 *
 * Generates cryptographically random 16-character passwords with a strict
 * 60/40 split:
 *   • 10 characters — standard ASCII (letters, digits, common symbols)
 *   • 6  characters — rare high-entropy Unicode from international/math/emoji blocks
 *
 * Unicode pools:
 *   Mathematical Alphanumeric Symbols  (U+1D400–U+1D7FF, sampled)
 *   Letterlike Symbols                 (U+2100–U+214F)
 *   Mathematical Operators             (U+2200–U+22FF)
 *   Supplemental Math Operators        (U+2A00–U+2AFF)
 *   Geometric Shapes                   (U+25A0–U+25FF)
 *   Miscellaneous Symbols              (U+2600–U+26FF)
 *   Dingbats                           (U+2700–U+27BF)
 *   Currency Symbols                   (U+20A0–U+20CF)
 *   Enclosed Alphanumerics             (U+2460–U+24FF)
 *   Greek Extended                     (U+1F00–U+1FFF)
 *   Cyrillic Supplement                (U+0500–U+052F)
 *   CJK Unified Ideographs (window)    (U+4E00–U+4E7F)
 *   Misc. Symbols & Pictographs        (U+1F300–U+1F3FF)
 *   Transport & Map Symbols            (U+1F680–U+1F6FF)
 *   Emoticons                          (U+1F600–U+1F64F)
 */

const crypto = require('crypto');

// ─── ASCII pool (60%) ─────────────────────────────────────────────────────────

const ASCII_POOL = [
  ...'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  ...'abcdefghijklmnopqrstuvwxyz',
  ...'0123456789',
  ...'!@#$%^&*()-_=+[]{}|;:,.<>?/~`',
];

// ─── Unicode pool (40%) ───────────────────────────────────────────────────────

const UNICODE_RANGES = [
  [0x1D400, 0x1D454], [0x1D456, 0x1D49C],
  [0x2100,  0x214F],
  [0x2200,  0x22FF],
  [0x2A00,  0x2AFF],
  [0x25A0,  0x25FF],
  [0x2600,  0x26FF],
  [0x2700,  0x27BF],
  [0x20A0,  0x20CF],
  [0x2460,  0x24FF],
  [0x1F00,  0x1FFF],
  [0x0500,  0x052F],
  [0x4E00,  0x4E7F],
  [0x1F300, 0x1F3FF],
  [0x1F680, 0x1F6FF],
  [0x1F600, 0x1F64F],
];

const TOTAL_UNICODE_SIZE = UNICODE_RANGES.reduce((a, [s, e]) => a + (e - s + 1), 0);

/** Cryptographically random Unicode character from the pool. */
function randomUnicodeChar() {
  let idx = Number(crypto.randomInt(0, TOTAL_UNICODE_SIZE));
  for (const [start, end] of UNICODE_RANGES) {
    const size = end - start + 1;
    if (idx < size) {
      const cp = start + idx;
      // Skip surrogates (safety net — our ranges don't include them)
      if (cp >= 0xD800 && cp <= 0xDFFF) return randomUnicodeChar();
      return String.fromCodePoint(cp);
    }
    idx -= size;
  }
  return '★'; // unreachable
}

/** Cryptographically random element from an array. */
function randomFrom(arr) {
  return arr[crypto.randomInt(0, arr.length)];
}

/** Fisher-Yates shuffle using crypto.randomInt. In-place. */
function cryptoShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Generate a 16-character password: 10 ASCII + 6 Unicode, shuffled.
 * @returns {string}
 */
function generatePassword() {
  const chars = [];
  for (let i = 0; i < 10; i++) chars.push(randomFrom(ASCII_POOL));
  for (let i = 0; i < 6;  i++) chars.push(randomUnicodeChar());
  cryptoShuffle(chars);
  return chars.join('');
}

/**
 * Analyse structural constraints of a password string.
 * @param {string} password
 * @returns {{ valid: boolean, asciiCount: number, unicodeCount: number, totalCodePoints: number }}
 */
function analyzePassword(password) {
  const codePoints = [...password];
  let asciiCount = 0, unicodeCount = 0;
  for (const ch of codePoints) {
    const cp = ch.codePointAt(0);
    (cp >= 0x21 && cp <= 0x7E) ? asciiCount++ : unicodeCount++;
  }
  return {
    valid: codePoints.length === 16 && asciiCount === 10 && unicodeCount === 6,
    asciiCount,
    unicodeCount,
    totalCodePoints: codePoints.length,
  };
}

module.exports = { generatePassword, analyzePassword };
