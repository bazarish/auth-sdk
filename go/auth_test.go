package bazarishauth

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"testing"
	"time"
)

type vector struct {
	SecretHex   string   `json:"secretHex"`
	Consumer    Consumer `json:"consumer"`
	Now         int64    `json:"now"`
	Challenge   string   `json:"challenge"`
	Blob        string   `json:"blob"`
	Fingerprint string   `json:"fingerprint"`
	Mldsa44Key  string   `json:"mldsa44PublicKey"`
}

func load(t *testing.T) (vector, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	secret, err := hex.DecodeString(v.SecretHex)
	if err != nil {
		t.Fatal(err)
	}
	return v, secret
}

func verifier(t *testing.T, secret []byte, consumer Consumer) *Verifier {
	t.Helper()
	result, err := NewVerifier(secret, consumer, NewMemoryNonceStore())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func rewrite(t *testing.T, encoded string, edit func(map[string]any)) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]any{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	edit(fields)
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(out)
}

func expect(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

func TestVectorVerifiesOnce(t *testing.T) {
	v, secret := load(t)
	subject := verifier(t, secret, v.Consumer)
	now := time.Unix(v.Now, 0)
	fingerprint, err := subject.Verify(v.Challenge, v.Blob, now)
	if err != nil || fingerprint != v.Fingerprint {
		t.Fatalf("got %q, %v", fingerprint, err)
	}
	_, err = subject.Verify(v.Challenge, v.Blob, now)
	expect(t, err, ErrAlreadyUsed)
}

func TestRefusals(t *testing.T) {
	v, secret := load(t)
	now := time.Unix(v.Now, 0)
	reordered := v.Consumer
	reordered.Place = []string{v.Consumer.Place[1], v.Consumer.Place[0]}
	otherSecret := append([]byte("another"), secret...)
	withPqKey := func(key func(keys map[string]any) any) string {
		return rewrite(t, v.Blob, func(fields map[string]any) {
			fields["k"] = rewrite(t, fields["k"].(string), func(keys map[string]any) { keys["pq"] = key(keys) })
		})
	}
	downgraded := withPqKey(func(keys map[string]any) any { return keys["c"] })
	weaker := withPqKey(func(map[string]any) any { return v.Mldsa44Key })
	renonced := rewrite(t, v.Blob, func(fields map[string]any) {
		fields["n"] = base64.StdEncoding.EncodeToString(make([]byte, nonceBytes))
	})
	flipped := func(field string) string {
		return rewrite(t, v.Blob, func(fields map[string]any) {
			signature, err := base64.StdEncoding.DecodeString(fields[field].(string))
			if err != nil {
				t.Fatal(err)
			}
			signature[0] ^= 1
			fields[field] = base64.StdEncoding.EncodeToString(signature)
		})
	}
	nextVersion := rewrite(t, v.Challenge, func(fields map[string]any) { fields["v"] = challengeVersion + 1 })
	nonAsciiTag := rewrite(t, v.Challenge, func(fields map[string]any) { fields["tag"] = "тег" })

	cases := []struct {
		name      string
		verifier  *Verifier
		challenge string
		blob      string
		now       time.Time
		want      error
	}{
		{"expired", verifier(t, secret, v.Consumer), v.Challenge, v.Blob, now.Add((windowSeconds + 1) * time.Second), ErrExpired},
		{"foreign consumer", verifier(t, secret, reordered), v.Challenge, v.Blob, now, ErrForeignConsumer},
		{"another secret", verifier(t, otherSecret, v.Consumer), v.Challenge, v.Blob, now, ErrUnknownChallenge},
		{"edited nonce", verifier(t, secret, v.Consumer), v.Challenge, renonced, now, ErrBadSignature},
		{"classical signature flipped", verifier(t, secret, v.Consumer), v.Challenge, flipped("c"), now, ErrBadSignature},
		{"pq signature flipped", verifier(t, secret, v.Consumer), v.Challenge, flipped("p"), now, ErrBadSignature},
		{"next version", verifier(t, secret, v.Consumer), nextVersion, v.Blob, now, ErrMalformedChallenge},
		{"non-ASCII tag", verifier(t, secret, v.Consumer), nonAsciiTag, v.Blob, now, ErrUnknownChallenge},
		{"classical key in the pq slot", verifier(t, secret, v.Consumer), v.Challenge, downgraded, now, ErrWrongKeyType},
		{"ML-DSA-44 key in the pq slot", verifier(t, secret, v.Consumer), v.Challenge, weaker, now, ErrWrongKeyType},
		{"challenge pasted as the blob", verifier(t, secret, v.Consumer), v.Challenge, v.Challenge, now, ErrMalformedBlob},
		{"not base64", verifier(t, secret, v.Consumer), "%%%", v.Blob, now, ErrMalformedChallenge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := c.verifier.Verify(c.challenge, c.blob, c.now)
			expect(t, err, c.want)
		})
	}
}

func TestBadBlobDoesNotBurnTheChallenge(t *testing.T) {
	v, secret := load(t)
	subject := verifier(t, secret, v.Consumer)
	now := time.Unix(v.Now, 0)
	_, err := subject.Verify(v.Challenge, v.Challenge, now)
	expect(t, err, ErrMalformedBlob)
	fingerprint, err := subject.Verify(v.Challenge, v.Blob, now)
	if err != nil || fingerprint != v.Fingerprint {
		t.Fatalf("got %q, %v", fingerprint, err)
	}
}

func TestIssuedChallengePassesUpToTheBlob(t *testing.T) {
	v, secret := load(t)
	subject := verifier(t, secret, v.Consumer)
	now := time.Unix(v.Now, 0)
	challenge, err := subject.Issue(now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = subject.Verify(challenge, "", now)
	expect(t, err, ErrMalformedBlob)
}

func TestConstructorRefusals(t *testing.T) {
	v, secret := load(t)
	tooMany := v.Consumer
	tooMany.Place = []string{"a", "b", "c", "d", "e"}
	newline := v.Consumer
	newline.Name = "panel\nplace: https://elsewhere"
	_, err := NewVerifier(secret[:secretMinBytes-1], v.Consumer, NewMemoryNonceStore())
	expect(t, err, ErrShortSecret)
	_, err = NewVerifier(secret, tooMany, NewMemoryNonceStore())
	expect(t, err, ErrInvalidConsumer)
	_, err = NewVerifier(secret, newline, NewMemoryNonceStore())
	expect(t, err, ErrInvalidConsumer)
}

func TestConsumerCodePoints(t *testing.T) {
	v, secret := load(t)
	named := func(character string) Consumer {
		consumer := v.Consumer
		consumer.Name = "panel" + character
		return consumer
	}
	placed := v.Consumer
	placed.Place = []string{v.Consumer.Place[0], "http://panel⁦.b32.i2p"}
	_, err := NewVerifier(secret, placed, NewMemoryNonceStore())
	expect(t, err, ErrInvalidConsumer)
	refused := []string{"\u0085", "\u009f", "؜", "‎", " ", " ", "‪", "‮", "⁦", "⁩", "\xed\xa0\x80"}
	for _, character := range refused {
		t.Run(strconv.QuoteToASCII(character), func(t *testing.T) {
			_, err := NewVerifier(secret, named(character), NewMemoryNonceStore())
			expect(t, err, ErrInvalidConsumer)
		})
	}
	allowed := []string{"‍", "‌", " ", "‧", " ", "⁥", "⁪"}
	for _, character := range allowed {
		t.Run(strconv.QuoteToASCII(character), func(t *testing.T) {
			verifier(t, secret, named(character))
		})
	}
}
