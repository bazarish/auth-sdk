use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bazarish_auth::{Consumer, Error, NONCE_BYTES, SECRET_MIN_BYTES, Verifier, WINDOW_SECONDS};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::mem::discriminant;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vector {
    secret_hex: String,
    consumer: Consumer,
    now: i64,
    challenge: String,
    blob: String,
    fingerprint: String,
    mldsa44_public_key: String,
}

fn load() -> (Vector, Vec<u8>) {
    let raw = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../testdata/vectors.json"
    ))
    .unwrap();
    let vector: Vector = serde_json::from_slice(&raw).unwrap();
    let secret = (0..vector.secret_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&vector.secret_hex[i..i + 2], 16).unwrap())
        .collect();
    (vector, secret)
}

fn rewrite(encoded: &str, edit: impl FnOnce(&mut Map<String, Value>)) -> String {
    let mut fields: Map<String, Value> =
        serde_json::from_slice(&STANDARD.decode(encoded).unwrap()).unwrap();
    edit(&mut fields);
    STANDARD.encode(serde_json::to_vec(&fields).unwrap())
}

#[test]
fn vector_verifies_once() {
    let (vector, secret) = load();
    let verifier = Verifier::new(&secret, &vector.consumer).unwrap();
    assert_eq!(
        verifier
            .verify(&vector.challenge, &vector.blob, vector.now)
            .unwrap(),
        vector.fingerprint
    );
    assert!(matches!(
        verifier.verify(&vector.challenge, &vector.blob, vector.now),
        Err(Error::AlreadyUsed)
    ));
}

#[test]
fn refusals() {
    let (vector, secret) = load();
    let (challenge, blob, now) = (vector.challenge.as_str(), vector.blob.as_str(), vector.now);
    let mut reordered = vector.consumer.clone();
    reordered.place.reverse();
    let other_secret = [b"another".as_slice(), &secret].concat();
    let renonced = rewrite(blob, |fields| {
        fields.insert("n".into(), Value::from(STANDARD.encode([0u8; NONCE_BYTES])));
    });
    let with_pq_key = |key: &dyn Fn(&Map<String, Value>) -> Value| {
        rewrite(blob, |fields| {
            let keys = rewrite(fields["k"].as_str().unwrap(), |keys| {
                keys.insert("pq".into(), key(keys));
            });
            fields.insert("k".into(), Value::from(keys));
        })
    };
    let downgraded = with_pq_key(&|keys| keys["c"].clone());
    let weaker = with_pq_key(&|_| Value::from(vector.mldsa44_public_key.as_str()));
    let flipped = |field: &str| {
        rewrite(blob, |fields| {
            let mut signature = STANDARD.decode(fields[field].as_str().unwrap()).unwrap();
            signature[0] ^= 1;
            fields.insert(field.into(), Value::from(STANDARD.encode(signature)));
        })
    };
    let next_version = rewrite(challenge, |fields| {
        let version = fields["v"].as_i64().unwrap();
        fields.insert("v".into(), Value::from(version + 1));
    });
    let non_ascii_tag = rewrite(challenge, |fields| {
        fields.insert("tag".into(), Value::from("тег"));
    });
    let fresh = || Verifier::new(&secret, &vector.consumer).unwrap();

    let cases = [
        (
            "expired",
            fresh().verify(challenge, blob, now + WINDOW_SECONDS + 1),
            Error::Expired,
        ),
        (
            "foreign consumer",
            Verifier::new(&secret, &reordered)
                .unwrap()
                .verify(challenge, blob, now),
            Error::ForeignConsumer,
        ),
        (
            "another secret",
            Verifier::new(&other_secret, &vector.consumer)
                .unwrap()
                .verify(challenge, blob, now),
            Error::UnknownChallenge,
        ),
        (
            "edited nonce",
            fresh().verify(challenge, &renonced, now),
            Error::BadSignature,
        ),
        (
            "classical signature flipped",
            fresh().verify(challenge, &flipped("c"), now),
            Error::BadSignature,
        ),
        (
            "pq signature flipped",
            fresh().verify(challenge, &flipped("p"), now),
            Error::BadSignature,
        ),
        (
            "next version",
            fresh().verify(&next_version, blob, now),
            Error::MalformedChallenge,
        ),
        (
            "non-ASCII tag",
            fresh().verify(&non_ascii_tag, blob, now),
            Error::UnknownChallenge,
        ),
        (
            "classical key in the pq slot",
            fresh().verify(challenge, &downgraded, now),
            Error::WrongKeyType,
        ),
        (
            "ML-DSA-44 key in the pq slot",
            fresh().verify(challenge, &weaker, now),
            Error::WrongKeyType,
        ),
        (
            "challenge pasted as the blob",
            fresh().verify(challenge, challenge, now),
            Error::MalformedBlob,
        ),
        (
            "not base64",
            fresh().verify("%%%", blob, now),
            Error::MalformedChallenge,
        ),
    ];
    for (name, result, expected) in cases {
        match result {
            Err(error) => assert_eq!(
                discriminant(&error),
                discriminant(&expected),
                "{name}: {error}"
            ),
            Ok(fingerprint) => panic!("{name}: verified as {fingerprint}"),
        }
    }
}

#[test]
fn bad_blob_does_not_burn_the_challenge() {
    let (vector, secret) = load();
    let verifier = Verifier::new(&secret, &vector.consumer).unwrap();
    assert!(matches!(
        verifier.verify(&vector.challenge, &vector.challenge, vector.now),
        Err(Error::MalformedBlob)
    ));
    assert_eq!(
        verifier
            .verify(&vector.challenge, &vector.blob, vector.now)
            .unwrap(),
        vector.fingerprint
    );
}

#[test]
fn issued_challenge_passes_up_to_the_blob() {
    let (vector, secret) = load();
    let verifier = Verifier::new(&secret, &vector.consumer).unwrap();
    let challenge = verifier.issue(vector.now).unwrap();
    assert!(matches!(
        verifier.verify(&challenge, "", vector.now),
        Err(Error::MalformedBlob)
    ));
}

#[test]
fn constructor_refusals() {
    let (vector, secret) = load();
    let mut too_many = vector.consumer.clone();
    too_many.place = ["a", "b", "c", "d", "e"].map(String::from).to_vec();
    let mut newline = vector.consumer.clone();
    newline.name = "panel\nplace: https://elsewhere".into();
    assert!(matches!(
        Verifier::new(&secret[..SECRET_MIN_BYTES - 1], &vector.consumer),
        Err(Error::ShortSecret)
    ));
    assert!(matches!(
        Verifier::new(&secret, &too_many),
        Err(Error::InvalidConsumer)
    ));
    assert!(matches!(
        Verifier::new(&secret, &newline),
        Err(Error::InvalidConsumer)
    ));
}

#[test]
fn consumer_code_points() {
    let (vector, secret) = load();
    let named = |character: char| {
        let mut consumer = vector.consumer.clone();
        consumer.name = format!("panel{character}");
        consumer
    };
    let mut placed = vector.consumer.clone();
    placed.place[1] = "http://panel\u{2066}.b32.i2p".into();
    assert!(matches!(
        Verifier::new(&secret, &placed),
        Err(Error::InvalidConsumer)
    ));
    let refused = [
        '\u{85}', '\u{9f}', '\u{61c}', '\u{200e}', '\u{2028}', '\u{2029}', '\u{202a}', '\u{202e}',
        '\u{2066}', '\u{2069}',
    ];
    for character in refused {
        assert!(
            matches!(
                Verifier::new(&secret, &named(character)),
                Err(Error::InvalidConsumer)
            ),
            "{character:?}"
        );
    }
    let allowed = [
        '\u{200d}', '\u{200c}', '\u{a0}', '\u{2027}', '\u{202f}', '\u{2065}', '\u{206a}',
    ];
    for character in allowed {
        assert!(
            Verifier::new(&secret, &named(character)).is_ok(),
            "{character:?}"
        );
    }
}
