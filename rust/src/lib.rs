use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::memcmp;
use openssl::pkey::{KeyType, PKey, Public};
use openssl::rand::rand_bytes;
use openssl::sha::sha256;
use openssl::sign::{Signer, Verifier as SignatureVerifier};
use serde::{Deserialize, Serialize};

const CHALLENGE_VERSION: i64 = 1;
pub const WINDOW_SECONDS: i64 = 300;
pub const NONCE_BYTES: usize = 16;
pub const SECRET_MIN_BYTES: usize = 32;
const NAME_MAX: usize = 96;
const PLACE_MAX: usize = 256;
const ROLE_MAX: usize = 48;
const PLACES_MAX: usize = 4;
const CONTROL_CHARACTERS_BELOW: u8 = 0x20;
const DELETE_CHARACTER: u8 = 0x7f;
const SIGNED_VERSION: &str = "v2";
const LOGIN_METHOD: &str = "BZ-LOGIN";
const LOGIN_PATH: &str = "/portal/login";
const BASE32_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
const BASE32_BITS: u32 = 5;
const BYTE_BITS: u32 = 8;

pub type StoreError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub enum Error {
    ShortSecret,
    InvalidConsumer,
    MalformedChallenge,
    ForeignConsumer,
    Expired,
    UnknownChallenge,
    MalformedBlob,
    WrongKeyType,
    BadSignature,
    AlreadyUsed,
    Crypto(ErrorStack),
    Store(StoreError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ShortSecret => f.write_str("the secret is shorter than 32 bytes"),
            Error::InvalidConsumer => f.write_str("the consumer breaks the protocol's limits"),
            Error::MalformedChallenge => f.write_str("this is not a login challenge"),
            Error::ForeignConsumer => f.write_str("the challenge names another consumer"),
            Error::Expired => f.write_str("expired"),
            Error::UnknownChallenge => f.write_str("the challenge was not issued here"),
            Error::MalformedBlob => f.write_str("this is not a login signature"),
            Error::WrongKeyType => f.write_str("a key of the wrong type"),
            Error::BadSignature => f.write_str("the signature does not verify"),
            Error::AlreadyUsed => f.write_str("the challenge has already been used"),
            Error::Crypto(error) => error.fmt(f),
            Error::Store(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

impl From<ErrorStack> for Error {
    fn from(error: ErrorStack) -> Self {
        Error::Crypto(error)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Consumer {
    pub name: String,
    pub place: Vec<String>,
    pub role: String,
}

impl Consumer {
    fn usable(&self) -> bool {
        usable_field(&self.name, NAME_MAX)
            && usable_field(&self.role, ROLE_MAX)
            && !self.place.is_empty()
            && self.place.len() <= PLACES_MAX
            && self
                .place
                .iter()
                .all(|place| usable_field(place, PLACE_MAX))
    }

    fn canonical(&self) -> String {
        serde_json::to_string(self).expect("a consumer always serializes")
    }
}

pub trait NonceStore {
    fn consume(&self, nonce: &str, now: i64, until: i64) -> Result<bool, StoreError>;
}

#[derive(Default)]
pub struct MemoryNonceStore {
    seen: Mutex<HashMap<String, i64>>,
}

impl NonceStore for MemoryNonceStore {
    fn consume(&self, nonce: &str, now: i64, until: i64) -> Result<bool, StoreError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| "the nonce store is poisoned")?;
        seen.retain(|_, expires| *expires >= now);
        if seen.contains_key(nonce) {
            return Ok(false);
        }
        seen.insert(nonce.to_owned(), until);
        Ok(true)
    }
}

pub struct Verifier<S: NonceStore = MemoryNonceStore> {
    secret: Vec<u8>,
    canonical: String,
    store: S,
}

impl Verifier<MemoryNonceStore> {
    pub fn new(secret: &[u8], consumer: &Consumer) -> Result<Self, Error> {
        Self::with_store(secret, consumer, MemoryNonceStore::default())
    }
}

impl<S: NonceStore> Verifier<S> {
    pub fn with_store(secret: &[u8], consumer: &Consumer, store: S) -> Result<Self, Error> {
        if secret.len() < SECRET_MIN_BYTES {
            return Err(Error::ShortSecret);
        }
        if !consumer.usable() {
            return Err(Error::InvalidConsumer);
        }
        Ok(Verifier {
            secret: secret.to_vec(),
            canonical: consumer.canonical(),
            store,
        })
    }

    pub fn issue(&self, now: i64) -> Result<String, Error> {
        let mut raw = [0u8; NONCE_BYTES];
        rand_bytes(&mut raw)?;
        let nonce = hex(&raw);
        let challenge = format!(
            r#"{{"consumer":{},"nonce":"{nonce}","tag":"{}","ts":{now},"v":{CHALLENGE_VERSION}}}"#,
            self.canonical,
            self.tag(&nonce, now)?
        );
        Ok(STANDARD.encode(challenge))
    }

    pub fn verify(&self, challenge: &str, blob: &str, now: i64) -> Result<String, Error> {
        #[derive(Deserialize)]
        struct Envelope {
            v: i64,
            nonce: String,
            ts: i64,
            consumer: Consumer,
            tag: String,
        }
        let envelope: Envelope = decode(challenge).ok_or(Error::MalformedChallenge)?;
        if envelope.v != CHALLENGE_VERSION || !envelope.consumer.usable() {
            return Err(Error::MalformedChallenge);
        }
        if envelope.consumer.canonical() != self.canonical {
            return Err(Error::ForeignConsumer);
        }
        if !fresh(envelope.ts, now) {
            return Err(Error::Expired);
        }
        let expected = self.tag(&envelope.nonce, envelope.ts)?;
        if envelope.tag.len() != expected.len()
            || !memcmp::eq(envelope.tag.as_bytes(), expected.as_bytes())
        {
            return Err(Error::UnknownChallenge);
        }
        let fingerprint = verify_blob(blob, challenge, now)?;
        let unused = self
            .store
            .consume(&envelope.nonce, now, envelope.ts + WINDOW_SECONDS)
            .map_err(Error::Store)?;
        if !unused {
            return Err(Error::AlreadyUsed);
        }
        Ok(fingerprint)
    }

    fn tag(&self, nonce: &str, ts: i64) -> Result<String, Error> {
        let key = PKey::hmac(&self.secret)?;
        let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
        signer.update(format!("{nonce}\n{ts}\n{}", self.canonical).as_bytes())?;
        Ok(hex(&signer.sign_to_vec()?))
    }
}

fn verify_blob(blob: &str, challenge: &str, now: i64) -> Result<String, Error> {
    #[derive(Deserialize)]
    struct Blob {
        k: String,
        t: String,
        n: String,
        c: String,
        p: String,
    }
    #[derive(Deserialize)]
    struct Keys {
        c: String,
        pq: String,
    }
    let fields: Blob = decode(blob).ok_or(Error::MalformedBlob)?;
    let keys: Keys = decode(&fields.k).ok_or(Error::MalformedBlob)?;
    let t: i64 = fields.t.parse().map_err(|_| Error::MalformedBlob)?;
    let classical_der = STANDARD.decode(&keys.c).map_err(|_| Error::MalformedBlob)?;
    let pq_der = STANDARD
        .decode(&keys.pq)
        .map_err(|_| Error::MalformedBlob)?;
    let classical_signature = STANDARD
        .decode(&fields.c)
        .map_err(|_| Error::MalformedBlob)?;
    let pq_signature = STANDARD
        .decode(&fields.p)
        .map_err(|_| Error::MalformedBlob)?;
    if !fresh(t, now) {
        return Err(Error::Expired);
    }
    let classical = PKey::public_key_from_der(&classical_der).map_err(|_| Error::MalformedBlob)?;
    let pq = PKey::public_key_from_der(&pq_der).map_err(|_| Error::MalformedBlob)?;
    if !classical.is_a(KeyType::ED25519) || !pq.is_a(KeyType::ML_DSA_65) {
        return Err(Error::WrongKeyType);
    }
    let digest = hex(&sha256(challenge.as_bytes()));
    let signed = format!(
        "{SIGNED_VERSION}\n{t}\n{LOGIN_METHOD}\n{LOGIN_PATH}\n{digest}\n{}\n",
        fields.n
    );
    if !signature_holds(&classical, signed.as_bytes(), &classical_signature)?
        || !signature_holds(&pq, signed.as_bytes(), &pq_signature)?
    {
        return Err(Error::BadSignature);
    }
    Ok(base32(&sha256(&[classical_der, pq_der].concat())))
}

fn signature_holds(key: &PKey<Public>, signed: &[u8], signature: &[u8]) -> Result<bool, Error> {
    let mut verifier = SignatureVerifier::new_without_digest(key)?;
    Ok(matches!(
        verifier.verify_oneshot(signature, signed),
        Ok(true)
    ))
}

fn usable_field(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && !value
            .bytes()
            .any(|byte| byte < CONTROL_CHARACTERS_BELOW || byte == DELETE_CHARACTER)
}

fn decode<T: for<'de> Deserialize<'de>>(encoded: &str) -> Option<T> {
    let raw = STANDARD.decode(encoded).ok()?;
    serde_json::from_slice(&raw).ok()
}

fn fresh(ts: i64, now: i64) -> bool {
    ts >= now - WINDOW_SECONDS && ts <= now + WINDOW_SECONDS
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn base32(bytes: &[u8]) -> String {
    let mask = (1u32 << BASE32_BITS) - 1;
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for &byte in bytes {
        buffer = (buffer << BYTE_BITS) | u32::from(byte);
        bits += BYTE_BITS;
        while bits >= BASE32_BITS {
            bits -= BASE32_BITS;
            out.push(char::from(
                BASE32_ALPHABET[((buffer >> bits) & mask) as usize],
            ));
        }
        buffer &= (1u32 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(
            BASE32_ALPHABET[((buffer << (BASE32_BITS - bits)) & mask) as usize],
        ));
    }
    out
}
