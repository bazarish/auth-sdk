import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { LoginError, NONCE_BYTES, SECRET_MIN_BYTES, Verifier, WINDOW_SECONDS } from '../index.js';

const vector = JSON.parse(readFileSync(new URL('../../testdata/vectors.json', import.meta.url)));
const secret = Buffer.from(vector.secretHex, 'hex');
const { consumer, now, challenge, blob } = vector;

function rewrite(encoded, edit) {
  const fields = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
  edit(fields);
  return Buffer.from(JSON.stringify(fields)).toString('base64');
}

async function refused(kind, verifier, testChallenge, testBlob, at = now) {
  await assert.rejects(verifier.verify(testChallenge, testBlob, at), (error) => error instanceof LoginError && error.kind === kind);
}

test('the vector verifies once', async () => {
  const verifier = new Verifier(secret, consumer);
  assert.equal(await verifier.verify(challenge, blob, now), vector.fingerprint);
  await refused('already_used', verifier, challenge, blob);
});

test('refusals', async (t) => {
  const reordered = { ...consumer, place: [...consumer.place].reverse() };
  const renonced = rewrite(blob, (fields) => { fields.n = Buffer.alloc(NONCE_BYTES).toString('base64'); });
  const withPqKey = (key) => rewrite(blob, (fields) => { fields.k = rewrite(fields.k, (keys) => { keys.pq = key(keys); }); });
  const flipped = (field) => rewrite(blob, (fields) => {
    const signature = Buffer.from(fields[field], 'base64');
    signature[0] ^= 1;
    fields[field] = signature.toString('base64');
  });
  const nextVersion = rewrite(challenge, (fields) => { fields.v += 1; });
  const nonAsciiTag = rewrite(challenge, (fields) => { fields.tag = 'тег'; });
  const cases = [
    ['expired', new Verifier(secret, consumer), challenge, blob, now + WINDOW_SECONDS + 1],
    ['foreign_consumer', new Verifier(secret, reordered), challenge, blob, now],
    ['unknown_challenge', new Verifier(Buffer.concat([Buffer.from('another'), secret]), consumer), challenge, blob, now],
    ['bad_signature', new Verifier(secret, consumer), challenge, renonced, now],
    ['bad_signature', new Verifier(secret, consumer), challenge, flipped('c'), now],
    ['bad_signature', new Verifier(secret, consumer), challenge, flipped('p'), now],
    ['malformed_challenge', new Verifier(secret, consumer), nextVersion, blob, now],
    ['unknown_challenge', new Verifier(secret, consumer), nonAsciiTag, blob, now],
    ['wrong_key_type', new Verifier(secret, consumer), challenge, withPqKey((keys) => keys.c), now],
    ['wrong_key_type', new Verifier(secret, consumer), challenge, withPqKey(() => vector.mldsa44PublicKey), now],
    ['malformed_blob', new Verifier(secret, consumer), challenge, challenge, now],
    ['malformed_challenge', new Verifier(secret, consumer), '%%%', blob, now],
  ];
  for (const [index, [kind, verifier, testChallenge, testBlob, at]] of cases.entries()) {
    await t.test(`${index}: ${kind}`, () => refused(kind, verifier, testChallenge, testBlob, at));
  }
});

test('a bad blob does not burn the challenge', async () => {
  const verifier = new Verifier(secret, consumer);
  await refused('malformed_blob', verifier, challenge, challenge);
  assert.equal(await verifier.verify(challenge, blob, now), vector.fingerprint);
});

test('an issued challenge passes up to the blob', async () => {
  const verifier = new Verifier(secret, consumer);
  await refused('malformed_blob', verifier, verifier.issue(now), '');
});

test('constructor refusals', () => {
  const cases = [
    ['short_secret', secret.subarray(0, SECRET_MIN_BYTES - 1), consumer],
    ['invalid_consumer', secret, { ...consumer, place: ['a', 'b', 'c', 'd', 'e'] }],
    ['invalid_consumer', secret, { ...consumer, name: 'panel\nplace: https://elsewhere' }],
  ];
  for (const [kind, testSecret, testConsumer] of cases) {
    assert.throws(() => new Verifier(testSecret, testConsumer), (error) => error.kind === kind);
  }
});

test('consumer code points', () => {
  const named = (character) => ({ ...consumer, name: `panel${character}` });
  const refused = ['\u0085', '\u009f', '؜', '‎', ' ', ' ', '‪', '‮', '⁦', '⁩', '\ud800']
    .map(named)
    .concat({ ...consumer, place: [consumer.place[0], 'http://panel⁦.b32.i2p'] });
  const allowed = ['‍', '‌', ' ', '‧', ' ', '⁥', '⁪'];
  for (const [index, testConsumer] of refused.entries()) {
    assert.throws(() => new Verifier(secret, testConsumer), (error) => error.kind === 'invalid_consumer', `refused ${index}`);
  }
  for (const [index, character] of allowed.entries()) {
    assert.doesNotThrow(() => new Verifier(secret, named(character)), `allowed ${index}`);
  }
});
