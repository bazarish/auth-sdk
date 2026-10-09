import base64
import json
import pathlib
import unittest

from bazarish_auth import CHALLENGE_VERSION, NONCE_BYTES, SECRET_MIN_BYTES, WINDOW_SECONDS, Consumer, LoginError, Verifier

VECTOR = json.loads((pathlib.Path(__file__).parents[2] / "testdata" / "vectors.json").read_text())
SECRET = bytes.fromhex(VECTOR["secretHex"])
CONSUMER = Consumer(VECTOR["consumer"]["name"], VECTOR["consumer"]["place"], VECTOR["consumer"]["role"])
NOW = VECTOR["now"]


def rewrite(encoded, edit):
    fields = json.loads(base64.b64decode(encoded))
    edit(fields)
    return base64.b64encode(json.dumps(fields).encode()).decode()


def with_pq_key(key):
    return rewrite(VECTOR["blob"], lambda fields: fields.update(k=rewrite(fields["k"], lambda keys: keys.update(pq=key(keys)))))


def flipped(field):
    def flip(fields):
        signature = bytearray(base64.b64decode(fields[field]))
        signature[0] ^= 1
        fields[field] = base64.b64encode(signature).decode()

    return rewrite(VECTOR["blob"], flip)


class VectorTest(unittest.TestCase):
    def refused(self, kind, verifier, challenge, blob, now=NOW):
        with self.assertRaises(LoginError) as caught:
            verifier.verify(challenge, blob, now)
        self.assertEqual(caught.exception.kind, kind)

    def test_vector_verifies_once(self):
        verifier = Verifier(SECRET, CONSUMER)
        self.assertEqual(verifier.verify(VECTOR["challenge"], VECTOR["blob"], NOW), VECTOR["fingerprint"])
        self.refused("already_used", verifier, VECTOR["challenge"], VECTOR["blob"])

    def test_refusals(self):
        challenge, blob = VECTOR["challenge"], VECTOR["blob"]
        reordered = Consumer(CONSUMER.name, list(reversed(CONSUMER.place)), CONSUMER.role)
        renonced = rewrite(blob, lambda fields: fields.update(n=base64.b64encode(bytes(NONCE_BYTES)).decode()))
        cases = [
            ("expired", Verifier(SECRET, CONSUMER), challenge, blob, NOW + WINDOW_SECONDS + 1),
            ("foreign_consumer", Verifier(SECRET, reordered), challenge, blob, NOW),
            ("unknown_challenge", Verifier(b"another" + SECRET, CONSUMER), challenge, blob, NOW),
            ("bad_signature", Verifier(SECRET, CONSUMER), challenge, renonced, NOW),
            ("bad_signature", Verifier(SECRET, CONSUMER), challenge, flipped("c"), NOW),
            ("bad_signature", Verifier(SECRET, CONSUMER), challenge, flipped("p"), NOW),
            ("malformed_challenge", Verifier(SECRET, CONSUMER), rewrite(challenge, lambda f: f.update(v=CHALLENGE_VERSION + 1)), blob, NOW),
            ("unknown_challenge", Verifier(SECRET, CONSUMER), rewrite(challenge, lambda f: f.update(tag="тег")), blob, NOW),
            ("wrong_key_type", Verifier(SECRET, CONSUMER), challenge, with_pq_key(lambda keys: keys["c"]), NOW),
            ("wrong_key_type", Verifier(SECRET, CONSUMER), challenge, with_pq_key(lambda keys: VECTOR["mldsa44PublicKey"]), NOW),
            ("malformed_blob", Verifier(SECRET, CONSUMER), challenge, challenge, NOW),
            ("malformed_challenge", Verifier(SECRET, CONSUMER), "%%%", blob, NOW),
        ]
        for kind, verifier, case_challenge, case_blob, now in cases:
            with self.subTest(kind):
                self.refused(kind, verifier, case_challenge, case_blob, now)

    def test_bad_blob_does_not_burn_the_challenge(self):
        verifier = Verifier(SECRET, CONSUMER)
        self.refused("malformed_blob", verifier, VECTOR["challenge"], VECTOR["challenge"])
        self.assertEqual(verifier.verify(VECTOR["challenge"], VECTOR["blob"], NOW), VECTOR["fingerprint"])

    def test_issued_challenge_passes_up_to_the_blob(self):
        verifier = Verifier(SECRET, CONSUMER)
        self.refused("malformed_blob", verifier, verifier.issue(NOW), "")

    def test_constructor_refusals(self):
        cases = [
            ("short_secret", SECRET[: SECRET_MIN_BYTES - 1], CONSUMER),
            ("invalid_consumer", SECRET, Consumer(CONSUMER.name, ["a", "b", "c", "d", "e"], CONSUMER.role)),
            ("invalid_consumer", SECRET, Consumer("panel\nplace: https://elsewhere", CONSUMER.place, CONSUMER.role)),
        ]
        for kind, secret, consumer in cases:
            with self.subTest(kind):
                with self.assertRaises(LoginError) as caught:
                    Verifier(secret, consumer)
                self.assertEqual(caught.exception.kind, kind)


if __name__ == "__main__":
    unittest.main()
