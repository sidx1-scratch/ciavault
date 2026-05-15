'use strict';

const path = require('path');

// Magic signature written at the start of every CIAVault payload
const MAGIC = Buffer.from('CIAVAULT1');

// Flag bits (1 byte)
const FLAG_ENCRYPTED = 0x01;

/**
 * Pack a secret file into a CIAVault payload buffer.
 *
 * Payload layout:
 *   [9 bytes]  magic: "CIAVAULT1"
 *   [1 byte ]  flags
 *   [4 bytes]  filename length (uint32 LE)
 *   [N bytes]  filename (utf-8)
 *   [4 bytes]  data length (uint32 LE)
 *   [N bytes]  file data
 */
function packPayload(filename, data, encrypted = false) {
  const nameBuf  = Buffer.from(path.basename(filename), 'utf8');
  const flags    = encrypted ? FLAG_ENCRYPTED : 0x00;

  const header = Buffer.allocUnsafe(MAGIC.length + 1 + 4 + nameBuf.length + 4);
  let offset = 0;

  MAGIC.copy(header, offset);                                offset += MAGIC.length;
  header.writeUInt8(flags, offset);                          offset += 1;
  header.writeUInt32LE(nameBuf.length, offset);              offset += 4;
  nameBuf.copy(header, offset);                              offset += nameBuf.length;
  header.writeUInt32LE(data.length, offset);

  return Buffer.concat([header, data]);
}

/**
 * Unpack a CIAVault payload buffer.
 * Returns { filename, data, encrypted }
 */
function unpackPayload(buf) {
  if (!buf.slice(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('No CIAVault payload found (magic mismatch)');
  }

  let offset = MAGIC.length;
  const flags      = buf.readUInt8(offset);                  offset += 1;
  const nameLen    = buf.readUInt32LE(offset);               offset += 4;
  const filename   = buf.slice(offset, offset + nameLen).toString('utf8'); offset += nameLen;
  const dataLen    = buf.readUInt32LE(offset);               offset += 4;
  const data       = buf.slice(offset, offset + dataLen);

  if (data.length < dataLen) {
    throw new Error('Payload is truncated or corrupted');
  }

  return {
    filename,
    data,
    encrypted: !!(flags & FLAG_ENCRYPTED),
  };
}

/** Return human-readable file size string */
function humanSize(bytes) {
  if (bytes < 1024)        return `${bytes} B`;
  if (bytes < 1024 ** 2)   return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3)   return `${(bytes / 1024 ** 2).toFixed(2)} MB`;
  return                          `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

module.exports = { packPayload, unpackPayload, humanSize, MAGIC };
