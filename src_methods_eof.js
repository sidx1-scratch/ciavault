'use strict';

/**
 * EOF (End-of-File) injection steganography.
 *
 * Works with ANY file type. The payload is appended after the carrier's
 * original content, sandwiched between two sentinel markers so it can
 * be found and stripped cleanly.
 *
 * Layout of the appended block:
 *   [8  bytes] START sentinel: 0xC1 0xA7 0xA0 0x17 <4 random bytes>
 *                              (the random bytes make each embed unique)
 *   [N  bytes] payload
 *   [4  bytes] payload length uint32 LE  ← placed AFTER payload so reveal
 *                                           can locate it from the file end
 *   [8  bytes] END sentinel:   0xC1 0xA7 0xA0 0x17 <same 4 random bytes>
 *
 * The 4-byte magic prefix  0xC1 0xA7 0xA0 0x17  ("CiAvault" nibbles)
 * is constant; the trailing 4 bytes are a nonce copied to both sentinels
 * so we can verify we found the right block.
 */

const MAGIC_PREFIX = Buffer.from([0xC1, 0xA7, 0xA0, 0x17]);
const SENTINEL_LEN = 8; // 4 magic + 4 nonce

function makeSentinel(nonce) {
  return Buffer.concat([MAGIC_PREFIX, nonce]);
}

/**
 * Append `payload` after `carrierBuf`.
 * Returns a new Buffer containing carrier + injected block.
 */
function hide(carrierBuf, payload) {
  const nonce     = require('crypto').randomBytes(4);
  const sentinel  = makeSentinel(nonce);

  const lenBuf    = Buffer.allocUnsafe(4);
  lenBuf.writeUInt32LE(payload.length, 0);

  return Promise.resolve(
    Buffer.concat([carrierBuf, sentinel, payload, lenBuf, sentinel])
  );
}

/**
 * Find and extract the injected payload from `carrierBuf`.
 * Returns { payload, strippedCarrier } where strippedCarrier
 * is the original carrier without the appended block.
 */
function reveal(carrierBuf) {
  // Scan backwards for the end sentinel
  const minOffset = SENTINEL_LEN + 4 + SENTINEL_LEN; // smallest possible block

  if (carrierBuf.length < minOffset) {
    return Promise.reject(new Error('File too small to contain an EOF payload'));
  }

  // The end sentinel's last byte is at the very end of the file
  const endSentinelEnd   = carrierBuf.length;
  const endSentinelStart = endSentinelEnd - SENTINEL_LEN;

  const endSentinel  = carrierBuf.slice(endSentinelStart, endSentinelEnd);
  const endMagic     = endSentinel.slice(0, 4);
  const endNonce     = endSentinel.slice(4, 8);

  if (!endMagic.equals(MAGIC_PREFIX)) {
    return Promise.reject(new Error('No CIAVault EOF payload found in this file'));
  }

  // Read payload length that precedes the end sentinel
  const lenOffset  = endSentinelStart - 4;
  if (lenOffset < 0) {
    return Promise.reject(new Error('Payload block is malformed'));
  }
  const payloadLen = carrierBuf.readUInt32LE(lenOffset);

  // Locate start sentinel
  const payloadStart     = lenOffset - payloadLen;
  const startSentinelEnd = payloadStart;
  const startSentinelStart = startSentinelEnd - SENTINEL_LEN;

  if (startSentinelStart < 0) {
    return Promise.reject(new Error('Payload block is malformed (start sentinel missing)'));
  }

  const startSentinel = carrierBuf.slice(startSentinelStart, startSentinelEnd);
  const startMagic    = startSentinel.slice(0, 4);
  const startNonce    = startSentinel.slice(4, 8);

  if (!startMagic.equals(MAGIC_PREFIX)) {
    return Promise.reject(new Error('Start sentinel magic mismatch — file may be corrupted'));
  }

  if (!startNonce.equals(endNonce)) {
    return Promise.reject(new Error('Sentinel nonce mismatch — file may be corrupted'));
  }

  const payload         = carrierBuf.slice(payloadStart, payloadStart + payloadLen);
  const strippedCarrier = carrierBuf.slice(0, startSentinelStart);

  return Promise.resolve({ payload, strippedCarrier });
}

/** EOF method has no hard capacity limit (only disk space) */
function capacity() {
  return Promise.resolve(Infinity);
}

module.exports = { hide, reveal, capacity };
