# Bazarish auth SDK

Server-side sign-in with a Bazarish key for Go, Rust, Python and JavaScript.
The protocol is specified in
[SignInWithKey](https://github.com/bazarish/docs-main/blob/main/api/SignInWithKey.md).

| Language | Directory | Minimum | Tests |
|---|---|---|---|
| Go | `go` | Go 1.27, golang.org/x/crypto | `go test ./...` |
| Rust | `rust` | Rust 1.85, OpenSSL 3.5 | `cargo test` |
| Python | `python` | Python 3.9, cryptography 48 | `python -m unittest discover -s tests` |
| JavaScript | `js` | Node.js 24.6 | `node --test` |

## Signing in

A site signs a user in with three calls:

1. Create a verifier from a secret of at least 32 random bytes and the consumer.
   The consumer is the site's name, up to four addresses it answers at, and the
   role being signed into.
2. Show the user the challenge that `issue` returns: a `bazarish://sign` link,
   as text, a link or a QR code. The user signs it in their Bazarish client and
   pastes the result back.
3. Pass the challenge and the pasted text to `verify`. It returns the signer's
   fingerprint or an error that names the reason.

A site that answers at a `.b32.i2p` address can let the client send the result
itself: issue the challenge with a callback on that address (`IssueWithCallback`
in Go, `issue_with_callback` in Rust, the second argument of `issue` in Python
and JavaScript). The address does not have to be one of the consumer's places.
The challenge's tag covers the callback, so `verify` refuses a challenge whose
callback was changed.

Both exchanges over I2P are sealed under a key the site makes for that one
challenge (`NewKey` / `new_key` / `newKey`) and keeps beside the challenge's
nonce until the sign-in ends:

- A link that hands the challenge over carries the key: `WithKey` / `with_key` /
  `withKey` appends `&key=` to it. A challenge with a callback is too dense for a
  QR code a phone camera reads reliably, so for a code show a link to it instead,
  `bazarish://sign?at=<host><path>` with the key appended, where the host is the
  callback's host. Answer `GET <path>` on that host with `SealChallenge` /
  `seal_challenge` / `sealChallenge` of the challenge as the whole body. The client
  refuses a link without a key and a challenge whose callback goes to another host.
- The client posts `{"nonce": ..., "sealed": ...}` to the callback. Find the key
  by `AnswerNonce` / `answer_nonce` / `answerNonce`, open the body with
  `OpenAnswer` / `open_answer` / `openAnswer`, and verify the challenge and blob it
  returns as in step 3. A body sealed under another key, or one that answers
  another challenge than its nonce, fails with `malformed_answer`.

The key is not part of the challenge; a challenge pasted into a form needs none.
The Go module takes ChaCha20-Poly1305 from `golang.org/x/crypto`, as the
standard library does not export it.

## Several processes

Every process that verifies logins for one consumer uses the same secret and the
same nonce store. The built-in store lives in the memory of one process. A shared
store implements `consume(nonce, now, until)`. It returns false for a nonce it
has seen and keeps a new one until `until`.

## Test vectors

The reference implementation in [common-cpp](https://github.com/bazarish/common-cpp)
produced `testdata/vectors.json`. The tests of every language check it.
