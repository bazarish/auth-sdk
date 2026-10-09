import base64
import binascii
import hashlib
import hmac
import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Sequence

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

__all__ = ["Consumer", "LoginError", "MemoryNonceStore", "Verifier"]

CHALLENGE_VERSION = 1
WINDOW_SECONDS = 300
NONCE_BYTES = 16
SECRET_MIN_BYTES = 32
NAME_MAX = 96
PLACE_MAX = 256
ROLE_MAX = 48
PLACES_MAX = 4
CONTROL_CHARACTERS_BELOW = 0x20
DELETE_CHARACTER = 0x7F
SIGNED_VERSION = "v2"
LOGIN_METHOD = "BZ-LOGIN"
LOGIN_PATH = "/portal/login"


class LoginError(Exception):
    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class Consumer:
    name: str
    place: Sequence[str]
    role: str

    def _usable(self):
        return (
            _usable_field(self.name, NAME_MAX)
            and _usable_field(self.role, ROLE_MAX)
            and isinstance(self.place, (list, tuple))
            and 0 < len(self.place) <= PLACES_MAX
            and all(_usable_field(place, PLACE_MAX) for place in self.place)
        )

    def _canonical(self):
        return _compact({"name": self.name, "place": list(self.place), "role": self.role})


class MemoryNonceStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._seen = {}

    def consume(self, nonce, now, until):
        with self._lock:
            self._seen = {seen: expires for seen, expires in self._seen.items() if expires >= now}
            if nonce in self._seen:
                return False
            self._seen[nonce] = until
            return True


class Verifier:
    def __init__(self, secret, consumer, store=None):
        if len(secret) < SECRET_MIN_BYTES:
            raise LoginError("short_secret", "the secret is shorter than 32 bytes")
        if not consumer._usable():
            raise LoginError("invalid_consumer", "the consumer breaks the protocol's limits")
        self._secret = bytes(secret)
        self._canonical = consumer._canonical()
        self._store = store if store is not None else MemoryNonceStore()

    def issue(self, now=None):
        now = int(time.time() if now is None else now)
        nonce = os.urandom(NONCE_BYTES).hex()
        challenge = {
            "consumer": json.loads(self._canonical),
            "nonce": nonce,
            "tag": self._tag(nonce, now),
            "ts": now,
            "v": CHALLENGE_VERSION,
        }
        return base64.b64encode(_compact(challenge).encode()).decode()

    def verify(self, challenge, blob, now=None):
        now = int(time.time() if now is None else now)
        envelope = _decode(challenge)
        consumer = _consumer_of(envelope)
        if consumer is None or not _is_int(envelope.get("ts")) or not isinstance(envelope.get("nonce"), str):
            raise LoginError("malformed_challenge", "this is not a login challenge")
        if consumer._canonical() != self._canonical:
            raise LoginError("foreign_consumer", "the challenge names another consumer")
        if not _fresh(envelope["ts"], now):
            raise LoginError("expired", "the challenge has expired")
        tag = envelope.get("tag")
        if not isinstance(tag, str) or not hmac.compare_digest(tag.encode(), self._tag(envelope["nonce"], envelope["ts"]).encode()):
            raise LoginError("unknown_challenge", "the challenge was not issued here")
        fingerprint = _verify_blob(blob, challenge, now)
        if not self._store.consume(envelope["nonce"], now, envelope["ts"] + WINDOW_SECONDS):
            raise LoginError("already_used", "the challenge has already been used")
        return fingerprint

    def _tag(self, nonce, ts):
        message = f"{nonce}\n{ts}\n{self._canonical}".encode()
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()


def _verify_blob(blob, challenge, now):
    malformed = LoginError("malformed_blob", "this is not a login signature")
    fields = _decode(blob)
    if not isinstance(fields, dict) or not all(isinstance(fields.get(name), str) for name in "ktncp"):
        raise malformed
    try:
        t = int(fields["t"], 10)
        keys = json.loads(base64.b64decode(fields["k"], validate=True))
        classical_der = base64.b64decode(keys["c"], validate=True)
        pq_der = base64.b64decode(keys["pq"], validate=True)
        classical_signature = base64.b64decode(fields["c"], validate=True)
        pq_signature = base64.b64decode(fields["p"], validate=True)
        classical = load_der_public_key(classical_der)
        pq = load_der_public_key(pq_der)
    except (ValueError, TypeError, KeyError, UnsupportedAlgorithm):
        raise malformed from None
    if not _fresh(t, now):
        raise LoginError("expired", "the signature has expired")
    if not isinstance(classical, Ed25519PublicKey) or not isinstance(pq, MLDSA65PublicKey):
        raise LoginError("wrong_key_type", "a key of the wrong type")
    digest = hashlib.sha256(challenge.encode()).hexdigest()
    signed = f"{SIGNED_VERSION}\n{t}\n{LOGIN_METHOD}\n{LOGIN_PATH}\n{digest}\n{fields['n']}\n".encode()
    try:
        classical.verify(classical_signature, signed)
        pq.verify(pq_signature, signed)
    except InvalidSignature:
        raise LoginError("bad_signature", "the signature does not verify") from None
    fingerprint = base64.b32encode(hashlib.sha256(classical_der + pq_der).digest())
    return fingerprint.decode().rstrip("=").lower()


def _consumer_of(envelope):
    if not isinstance(envelope, dict) or not _is_int(envelope.get("v")) or envelope["v"] != CHALLENGE_VERSION:
        return None
    fields = envelope.get("consumer")
    if not isinstance(fields, dict) or not isinstance(fields.get("place"), list):
        return None
    consumer = Consumer(fields.get("name"), tuple(fields["place"]), fields.get("role"))
    return consumer if consumer._usable() else None


def _usable_field(value, limit):
    return (
        isinstance(value, str)
        and 0 < len(value.encode()) <= limit
        and not any(ord(character) < CONTROL_CHARACTERS_BELOW or ord(character) == DELETE_CHARACTER for character in value)
    )


def _decode(encoded):
    try:
        return json.loads(base64.b64decode(encoded, validate=True))
    except (ValueError, TypeError, binascii.Error):
        return None


def _compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _fresh(ts, now):
    return now - WINDOW_SECONDS <= ts <= now + WINDOW_SECONDS
