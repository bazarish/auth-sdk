import { createHash, createHmac, createPublicKey, randomBytes, timingSafeEqual, verify } from 'node:crypto';

const CHALLENGE_VERSION = 1;
export const WINDOW_SECONDS = 300;
export const NONCE_BYTES = 16;
export const SECRET_MIN_BYTES = 32;
const NAME_MAX = 96;
const PLACE_MAX = 256;
const ROLE_MAX = 48;
const PLACES_MAX = 4;
const SIGNED_VERSION = 'v2';
const LOGIN_METHOD = 'BZ-LOGIN';
const LOGIN_PATH = '/portal/login';
const CHALLENGE_PREFIX = 'bazarish://sign?c=';
const CALLBACK_MAX = 256;
const CALLBACK_SCHEME = 'http://';
const B32_HOST = /^(?:[a-z2-7]{52}|[a-z2-7]{56})\.b32\.i2p$/;
const CALLBACK_PATH = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/?%]*$/;
const BASE64URL = /^[A-Za-z0-9_-]+$/;
// SignInWithKey.md, "The consumer".
const FORBIDDEN_CODE_POINTS = [
  [0x0000, 0x001f],
  [0x007f, 0x009f],
  [0x061c, 0x061c],
  [0x200e, 0x200f],
  [0x2028, 0x202e],
  [0x2066, 0x2069],
];
const MILLISECONDS_PER_SECOND = 1000;
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const BASE32_BITS = 5;
const BYTE_BITS = 8;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export class LoginError extends Error {
  constructor(kind, message) {
    super(message);
    this.name = 'LoginError';
    this.kind = kind;
  }
}

export class MemoryNonceStore {
  #seen = new Map();

  consume(nonce, now, until) {
    for (const [seen, expires] of this.#seen) {
      if (expires < now) {
        this.#seen.delete(seen);
      }
    }
    if (this.#seen.has(nonce)) {
      return false;
    }
    this.#seen.set(nonce, until);
    return true;
  }
}

export class Verifier {
  #secret;
  #canonical;
  #places;
  #store;

  constructor(secret, consumer, store = new MemoryNonceStore()) {
    if (Buffer.byteLength(secret) < SECRET_MIN_BYTES) {
      throw new LoginError('short_secret', 'the secret is shorter than 32 bytes');
    }
    if (!usable(consumer)) {
      throw new LoginError('invalid_consumer', "the consumer breaks the protocol's limits");
    }
    this.#secret = Buffer.from(secret);
    this.#canonical = canonical(consumer);
    this.#places = [...consumer.place];
    this.#store = store;
  }

  // A callback names where the client may send the blob itself.
  issue(now = currentSeconds(), callback = undefined) {
    if (callback !== undefined && !callbackUsable(callback, this.#places)) {
      throw new LoginError('invalid_callback', "the callback is not one of the consumer's I2P places");
    }
    const ts = Math.floor(now);
    const nonce = randomBytes(NONCE_BYTES).toString('hex');
    const head = callback === undefined ? '' : `"callback":"${callback}",`;
    const challenge = `{${head}"consumer":${this.#canonical},"nonce":"${nonce}","tag":"${this.#tag(nonce, ts)}",`
      + `"ts":${ts},"v":${CHALLENGE_VERSION}}`;
    return CHALLENGE_PREFIX + Buffer.from(challenge).toString('base64url');
  }

  async verify(challenge, blob, now = currentSeconds()) {
    const envelope = decodeChallenge(challenge);
    if (envelope?.v !== CHALLENGE_VERSION || !usable(envelope.consumer)
        || !Number.isSafeInteger(envelope.ts) || typeof envelope.nonce !== 'string') {
      throw new LoginError('malformed_challenge', 'this is not a login challenge');
    }
    if (canonical(envelope.consumer) !== this.#canonical) {
      throw new LoginError('foreign_consumer', 'the challenge names another consumer');
    }
    if (!fresh(envelope.ts, now)) {
      throw new LoginError('expired', 'the challenge has expired');
    }
    const expected = Buffer.from(this.#tag(envelope.nonce, envelope.ts));
    const presented = Buffer.from(String(envelope.tag));
    if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) {
      throw new LoginError('unknown_challenge', 'the challenge was not issued here');
    }
    const fingerprint = verifyBlob(blob, challenge, now);
    if (!await this.#store.consume(envelope.nonce, now, envelope.ts + WINDOW_SECONDS)) {
      throw new LoginError('already_used', 'the challenge has already been used');
    }
    return fingerprint;
  }

  #tag(nonce, ts) {
    return createHmac('sha256', this.#secret).update(`${nonce}\n${ts}\n${this.#canonical}`).digest('hex');
  }
}

function verifyBlob(blob, challenge, now) {
  const malformed = new LoginError('malformed_blob', 'this is not a login signature');
  const fields = decode(blob);
  if (!['k', 't', 'n', 'c', 'p'].every((name) => typeof fields?.[name] === 'string') || !/^\d+$/.test(fields.t)) {
    throw malformed;
  }
  const keys = decode(fields.k);
  if (![keys?.c, keys?.pq, fields.c, fields.p].every((value) => typeof value === 'string' && BASE64.test(value))) {
    throw malformed;
  }
  const t = Number(fields.t);
  if (!fresh(t, now)) {
    throw new LoginError('expired', 'the signature has expired');
  }
  const classicalDer = Buffer.from(keys.c, 'base64');
  const pqDer = Buffer.from(keys.pq, 'base64');
  let classical;
  let pq;
  try {
    classical = createPublicKey({ key: classicalDer, format: 'der', type: 'spki' });
    pq = createPublicKey({ key: pqDer, format: 'der', type: 'spki' });
  } catch {
    throw malformed;
  }
  if (classical.asymmetricKeyType !== 'ed25519' || pq.asymmetricKeyType !== 'ml-dsa-65') {
    throw new LoginError('wrong_key_type', 'a key of the wrong type');
  }
  const digest = createHash('sha256').update(challenge).digest('hex');
  const signed = Buffer.from(`${SIGNED_VERSION}\n${t}\n${LOGIN_METHOD}\n${LOGIN_PATH}\n${digest}\n${fields.n}\n`);
  if (!verify(null, signed, classical, Buffer.from(fields.c, 'base64'))
      || !verify(null, signed, pq, Buffer.from(fields.p, 'base64'))) {
    throw new LoginError('bad_signature', 'the signature does not verify');
  }
  return base32(createHash('sha256').update(classicalDer).update(pqDer).digest());
}

function usable(consumer) {
  return usableField(consumer?.name, NAME_MAX) && usableField(consumer?.role, ROLE_MAX)
    && Array.isArray(consumer.place) && consumer.place.length > 0 && consumer.place.length <= PLACES_MAX
    && consumer.place.every((place) => usableField(place, PLACE_MAX));
}

function usableField(value, limit) {
  if (typeof value !== 'string' || value === '' || !value.isWellFormed() || Buffer.byteLength(value) > limit) {
    return false;
  }
  return ![...value].some((character) => {
    const codePoint = character.codePointAt(0);
    return FORBIDDEN_CODE_POINTS.some(([first, last]) => codePoint >= first && codePoint <= last);
  });
}

function canonical(consumer) {
  return JSON.stringify({ name: consumer.name, place: consumer.place, role: consumer.role });
}

function callbackUsable(callback, places) {
  if (typeof callback !== 'string' || callback.length > CALLBACK_MAX || !callback.startsWith(CALLBACK_SCHEME)) {
    return false;
  }
  const rest = callback.slice(CALLBACK_SCHEME.length);
  const slash = rest.indexOf('/');
  if (slash < 0) {
    return false;
  }
  const host = rest.slice(0, slash);
  return B32_HOST.test(host) && CALLBACK_PATH.test(rest.slice(slash))
    && places.some((place) => placeHost(place) === host);
}

function placeHost(place) {
  let rest = place;
  if (rest.startsWith(CALLBACK_SCHEME)) {
    rest = rest.slice(CALLBACK_SCHEME.length);
  } else if (rest.includes('://')) {
    return undefined;
  }
  return rest.split('/')[0];
}

function decodeChallenge(challenge) {
  if (typeof challenge !== 'string' || !challenge.startsWith(CHALLENGE_PREFIX)) {
    return undefined;
  }
  const encoded = challenge.slice(CHALLENGE_PREFIX.length);
  if (!BASE64URL.test(encoded)) {
    return undefined;
  }
  try {
    return JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    return undefined;
  }
}

function decode(encoded) {
  if (typeof encoded !== 'string' || !BASE64.test(encoded)) {
    return undefined;
  }
  try {
    return JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
  } catch {
    return undefined;
  }
}

function base32(bytes) {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << BYTE_BITS) | byte;
    bits += BYTE_BITS;
    while (bits >= BASE32_BITS) {
      bits -= BASE32_BITS;
      out += BASE32_ALPHABET[(buffer >> bits) & ((1 << BASE32_BITS) - 1)];
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(buffer << (BASE32_BITS - bits)) & ((1 << BASE32_BITS) - 1)];
  }
  return out;
}

function fresh(ts, now) {
  return ts >= now - WINDOW_SECONDS && ts <= now + WINDOW_SECONDS;
}

function currentSeconds() {
  return Math.floor(Date.now() / MILLISECONDS_PER_SECOND);
}
