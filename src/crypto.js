import { createHash, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';

// No look-alikes: O/0, I/1.
export const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const SHORT_CODE_LENGTH = 8;

export const sha256 = (s) => createHash('sha256').update(s).digest('hex');
export const newToken = () => randomBytes(32).toString('base64url');
export const newId = () => randomBytes(12).toString('base64url');

export function newShortCode() {
  let c = '';
  for (let i = 0; i < SHORT_CODE_LENGTH; i++) c += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  return c;
}

// Users type codes by hand: ignore case, spaces and dashes.
export const normalizeShortCode = (s) => String(s).toUpperCase().replace(/[\s-]/g, '');

export function safeEqualHex(a, b) {
  const ba = Buffer.from(a, 'hex');
  const bb = Buffer.from(b, 'hex');
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}
