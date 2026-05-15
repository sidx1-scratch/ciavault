'use strict';

/**
 * LSB (Least Significant Bit) steganography for PNG images.
 *
 * Each bit of the payload is embedded into the LSB of the R, G, B
 * channels of each pixel (alpha is left untouched to avoid transparency issues).
 * That gives us floor(width * height * 3 / 8) bytes of capacity.
 *
 * We also embed a 4-byte LE uint32 at the very start (in the first
 * 32 bits × 3 channels = 96 channel LSBs) that stores the payload length,
 * so we know exactly how many bits to read back.
 */

const PNG  = require('pngjs').PNG;
const fs   = require('fs');

// Number of channels we use (R, G, B — skip alpha)
const CHANNELS_USED = 3;

/** Read bit `i` from buffer */
function getBit(buf, i) {
  return (buf[i >> 3] >> (7 - (i & 7))) & 1;
}

/** Set bit `i` in buffer to value `v` (0 or 1) */
function setBit(buf, i, v) {
  const byte = i >> 3;
  const shift = 7 - (i & 7);
  buf[byte] = (buf[byte] & ~(1 << shift)) | ((v & 1) << shift);
}

/**
 * Embed `payload` into PNG image data.
 * Returns a Buffer containing the new PNG file.
 */
function hide(carrierBuf, payload) {
  return new Promise((resolve, reject) => {
    const png = new PNG();
    png.parse(carrierBuf, (err, img) => {
      if (err) return reject(new Error(`Failed to parse PNG: ${err.message}`));

      const totalPixels = img.width * img.height;
      const capacity    = Math.floor((totalPixels * CHANNELS_USED) / 8);
      // We reserve 4 bytes at the start for the length prefix
      const maxData     = capacity - 4;

      if (payload.length > maxData) {
        return reject(
          new Error(
            `Payload too large for this image.\n` +
            `  Image capacity : ${maxData} bytes\n` +
            `  Payload size   : ${payload.length} bytes\n` +
            `  Use a larger PNG or switch to --method eof`
          )
        );
      }

      // Build a combined buffer: [4-byte length LE] + [payload]
      const combined = Buffer.allocUnsafe(4 + payload.length);
      combined.writeUInt32LE(payload.length, 0);
      payload.copy(combined, 4);

      // Channel index: pixels are stored as [R, G, B, A, R, G, B, A, ...]
      // We only touch channels 0,1,2 (R,G,B) within each pixel
      let bitIndex = 0;

      outer:
      for (let px = 0; px < totalPixels; px++) {
        const base = px * 4; // RGBA stride
        for (let ch = 0; ch < CHANNELS_USED; ch++) {
          if (bitIndex >= combined.length * 8) break outer;
          const bit = getBit(combined, bitIndex++);
          img.data[base + ch] = (img.data[base + ch] & 0xFE) | bit;
        }
      }

      // Re-encode to PNG
      const chunks = [];
      const out    = new PNG({ width: img.width, height: img.height });
      out.data      = img.data;
      out.on('data', chunk => chunks.push(chunk));
      out.on('end',  ()    => resolve(Buffer.concat(chunks)));
      out.on('error', reject);
      out.pack();
    });
  });
}

/**
 * Extract a payload previously embedded with `hide`.
 * Returns a Buffer containing the raw payload.
 */
function reveal(carrierBuf) {
  return new Promise((resolve, reject) => {
    const png = new PNG();
    png.parse(carrierBuf, (err, img) => {
      if (err) return reject(new Error(`Failed to parse PNG: ${err.message}`));

      const totalPixels = img.width * img.height;

      // Helper: extract `numBits` bits starting at pixel-channel offset `startBit`
      function extractBits(startBit, numBits) {
        const out = Buffer.alloc(Math.ceil(numBits / 8));
        let bitIndex = 0;
        const startPx  = Math.floor(startBit / CHANNELS_USED);
        const startCh  = startBit % CHANNELS_USED;

        for (let px = startPx; px < totalPixels && bitIndex < numBits; px++) {
          const base   = px * 4;
          const chFrom = (px === startPx) ? startCh : 0;
          for (let ch = chFrom; ch < CHANNELS_USED && bitIndex < numBits; ch++) {
            setBit(out, bitIndex++, img.data[base + ch] & 1);
          }
        }
        return out;
      }

      // Read 4-byte length prefix (first 32 bits = 32 channel-LSBs)
      const lenBuf    = extractBits(0, 32);
      const payloadLen = lenBuf.readUInt32LE(0);

      const capacity = Math.floor((totalPixels * CHANNELS_USED) / 8) - 4;
      if (payloadLen === 0 || payloadLen > capacity) {
        return reject(new Error('No valid CIAVault payload detected in this image'));
      }

      // Read payload bits (starting at bit 32)
      const payloadBuf = extractBits(32, payloadLen * 8);
      resolve(payloadBuf.slice(0, payloadLen));
    });
  });
}

/** Return max bytes this PNG can carry */
function capacity(carrierBuf) {
  return new Promise((resolve, reject) => {
    const png = new PNG();
    png.parse(carrierBuf, (err, img) => {
      if (err) return reject(err);
      resolve(Math.floor((img.width * img.height * CHANNELS_USED) / 8) - 4);
    });
  });
}

module.exports = { hide, reveal, capacity };
