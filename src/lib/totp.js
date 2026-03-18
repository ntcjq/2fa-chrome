/**
 * TOTP (RFC 6238) using Web Crypto API.
 * Base32 (RFC 4648) decode + HMAC-SHA1.
 */
const TOTP = (function () {
  const DEFAULT_STEP = 30;
  const DEFAULT_DIGITS = 6;

  const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function base32Decode(str) {
    str = str.replace(/\s/g, '').toUpperCase().replace(/=+$/, '');
    let bits = 0;
    let value = 0;
    const output = [];
    for (let i = 0; i < str.length; i++) {
      const idx = BASE32_ALPHABET.indexOf(str[i]);
      if (idx === -1) continue;
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        output.push((value >>> bits) & 0xff);
      }
    }
    return new Uint8Array(output);
  }

  function uint64Be(n) {
    const view = new DataView(new ArrayBuffer(8));
    view.setBigUint64(0, BigInt(n), false);
    return new Uint8Array(view.buffer);
  }

  async function hmacSha1(key, data) {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', cryptoKey, data);
    return new Uint8Array(sig);
  }

  function dynamicTruncate(hash, digits) {
    const offset = hash[hash.length - 1] & 0x0f;
    const p = (hash[offset] & 0x7f) << 24 |
      (hash[offset + 1] & 0xff) << 16 |
      (hash[offset + 2] & 0xff) << 8 |
      (hash[offset + 3] & 0xff);
    return p % Math.pow(10, digits);
  }

  function padCode(code, digits) {
    return String(code).padStart(digits, '0');
  }

  /**
   * Get current TOTP code for a base32-encoded secret.
   * @param {string} secretBase32 - Base32-encoded secret
   * @returns {Promise<string>} 6-digit code
   */
  async function getTOTP(secretBase32, options) {
    const period = options && Number(options.period) > 0 ? Number(options.period) : DEFAULT_STEP;
    const digits = options && Number(options.digits) > 0 ? Number(options.digits) : DEFAULT_DIGITS;
    const key = base32Decode(secretBase32);
    if (key.length === 0) return '------';
    const counter = Math.floor(Date.now() / 1000 / period);
    const data = uint64Be(counter);
    const hash = await hmacSha1(key, data);
    const code = dynamicTruncate(hash, digits);
    return padCode(code, digits);
  }

  /**
   * Get remaining seconds in current 30s window (1–30).
   * @returns {number}
   */
  function getRemainingSeconds(period) {
    const step = Number(period) > 0 ? Number(period) : DEFAULT_STEP;
    const elapsed = Math.floor(Date.now() / 1000) % step;
    return step - elapsed;
  }

  return {
    getTOTP,
    getRemainingSeconds,
    base32Decode,
  };
})();
