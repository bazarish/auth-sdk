package bazarishauth

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	challengeVersion = 1
	windowSeconds    = 300
	nonceBytes       = 16
	secretMinBytes   = 32
	nameMax          = 96
	placeMax         = 256
	roleMax          = 48
	placesMax        = 4
	signedVersion    = "v2"
	loginMethod      = "BZ-LOGIN"
	loginPath        = "/portal/login"
)

// SignInWithKey.md, "The consumer".
var forbiddenCodePoints = []struct{ first, last rune }{
	{0x0000, 0x001f},
	{0x007f, 0x009f},
	{0x061c, 0x061c},
	{0x200e, 0x200f},
	{0x2028, 0x202e},
	{0x2066, 0x2069},
}

var (
	ErrInvalidConsumer    = errors.New("bazarishauth: the consumer breaks the protocol's limits")
	ErrShortSecret        = errors.New("bazarishauth: the secret is shorter than 32 bytes")
	ErrMalformedChallenge = errors.New("bazarishauth: this is not a login challenge")
	ErrForeignConsumer    = errors.New("bazarishauth: the challenge names another consumer")
	ErrExpired            = errors.New("bazarishauth: expired")
	ErrUnknownChallenge   = errors.New("bazarishauth: the challenge was not issued here")
	ErrMalformedBlob      = errors.New("bazarishauth: this is not a login signature")
	ErrWrongKeyType       = errors.New("bazarishauth: a key of the wrong type")
	ErrBadSignature       = errors.New("bazarishauth: the signature does not verify")
	ErrAlreadyUsed        = errors.New("bazarishauth: the challenge has already been used")
)

type Consumer struct {
	Name  string   `json:"name"`
	Place []string `json:"place"`
	Role  string   `json:"role"`
}

type NonceStore interface {
	Consume(nonce string, now, until time.Time) (bool, error)
}

type MemoryNonceStore struct {
	mutex sync.Mutex
	seen  map[string]time.Time
}

func NewMemoryNonceStore() *MemoryNonceStore {
	return &MemoryNonceStore{seen: make(map[string]time.Time)}
}

func (s *MemoryNonceStore) Consume(nonce string, now, until time.Time) (bool, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	for seen, expires := range s.seen {
		if expires.Before(now) {
			delete(s.seen, seen)
		}
	}
	if _, found := s.seen[nonce]; found {
		return false, nil
	}
	s.seen[nonce] = until
	return true, nil
}

type Verifier struct {
	secret    []byte
	canonical string
	store     NonceStore
}

func NewVerifier(secret []byte, consumer Consumer, store NonceStore) (*Verifier, error) {
	if len(secret) < secretMinBytes {
		return nil, ErrShortSecret
	}
	if !consumer.usable() {
		return nil, ErrInvalidConsumer
	}
	return &Verifier{
		secret:    append([]byte(nil), secret...),
		canonical: consumer.canonical(),
		store:     store,
	}, nil
}

func (v *Verifier) Issue(now time.Time) (string, error) {
	raw := make([]byte, nonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(raw)
	ts := now.Unix()
	challenge := `{"consumer":` + v.canonical + `,"nonce":"` + nonce + `","tag":"` + v.tag(nonce, ts) +
		`","ts":` + strconv.FormatInt(ts, 10) + `,"v":` + strconv.Itoa(challengeVersion) + `}`
	return base64.StdEncoding.EncodeToString([]byte(challenge)), nil
}

func (v *Verifier) Verify(challenge, blob string, now time.Time) (string, error) {
	var envelope struct {
		V        int       `json:"v"`
		Nonce    string    `json:"nonce"`
		Ts       int64     `json:"ts"`
		Consumer *Consumer `json:"consumer"`
		Tag      string    `json:"tag"`
	}
	if decodeJSON(challenge, &envelope) != nil || envelope.V != challengeVersion ||
		envelope.Consumer == nil || !envelope.Consumer.usable() {
		return "", ErrMalformedChallenge
	}
	if envelope.Consumer.canonical() != v.canonical {
		return "", ErrForeignConsumer
	}
	if !fresh(envelope.Ts, now) {
		return "", ErrExpired
	}
	if !hmac.Equal([]byte(envelope.Tag), []byte(v.tag(envelope.Nonce, envelope.Ts))) {
		return "", ErrUnknownChallenge
	}
	fingerprint, err := verifyBlob(blob, challenge, now)
	if err != nil {
		return "", err
	}
	unused, err := v.store.Consume(envelope.Nonce, now, time.Unix(envelope.Ts+windowSeconds, 0))
	if err != nil {
		return "", err
	}
	if !unused {
		return "", ErrAlreadyUsed
	}
	return fingerprint, nil
}

func (v *Verifier) tag(nonce string, ts int64) string {
	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(nonce + "\n" + strconv.FormatInt(ts, 10) + "\n" + v.canonical))
	return hex.EncodeToString(mac.Sum(nil))
}

func (c Consumer) usable() bool {
	if !usableField(c.Name, nameMax) || !usableField(c.Role, roleMax) {
		return false
	}
	if len(c.Place) == 0 || len(c.Place) > placesMax {
		return false
	}
	for _, place := range c.Place {
		if !usableField(place, placeMax) {
			return false
		}
	}
	return true
}

func usableField(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, codePoint := range value {
		for _, forbidden := range forbiddenCodePoints {
			if codePoint >= forbidden.first && codePoint <= forbidden.last {
				return false
			}
		}
	}
	return true
}

var jsonEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`)

func (c Consumer) canonical() string {
	quoted := make([]string, len(c.Place))
	for i, place := range c.Place {
		quoted[i] = `"` + jsonEscaper.Replace(place) + `"`
	}
	return `{"name":"` + jsonEscaper.Replace(c.Name) + `","place":[` + strings.Join(quoted, ",") +
		`],"role":"` + jsonEscaper.Replace(c.Role) + `"}`
}

func verifyBlob(blob, challenge string, now time.Time) (string, error) {
	var fields struct {
		K string `json:"k"`
		T string `json:"t"`
		N string `json:"n"`
		C string `json:"c"`
		P string `json:"p"`
	}
	if decodeJSON(blob, &fields) != nil || fields.K == "" || fields.N == "" || fields.C == "" || fields.P == "" {
		return "", ErrMalformedBlob
	}
	t, err := strconv.ParseInt(fields.T, 10, 64)
	if err != nil {
		return "", ErrMalformedBlob
	}
	if !fresh(t, now) {
		return "", ErrExpired
	}
	var keys struct {
		C  string `json:"c"`
		PQ string `json:"pq"`
	}
	if decodeJSON(fields.K, &keys) != nil {
		return "", ErrMalformedBlob
	}
	classicalDer, errClassical := base64.StdEncoding.DecodeString(keys.C)
	pqDer, errPq := base64.StdEncoding.DecodeString(keys.PQ)
	classicalSignature, errClassicalSignature := base64.StdEncoding.DecodeString(fields.C)
	pqSignature, errPqSignature := base64.StdEncoding.DecodeString(fields.P)
	if errors.Join(errClassical, errPq, errClassicalSignature, errPqSignature) != nil {
		return "", ErrMalformedBlob
	}
	classical, errClassical := x509.ParsePKIXPublicKey(classicalDer)
	pq, errPq := x509.ParsePKIXPublicKey(pqDer)
	if errors.Join(errClassical, errPq) != nil {
		return "", ErrMalformedBlob
	}
	classicalKey, isEd25519 := classical.(ed25519.PublicKey)
	pqKey, isMldsa := pq.(*mldsa.PublicKey)
	if !isEd25519 || !isMldsa || pqKey.Parameters() != mldsa.MLDSA65() {
		return "", ErrWrongKeyType
	}
	digest := sha256.Sum256([]byte(challenge))
	signed := []byte(signedVersion + "\n" + strconv.FormatInt(t, 10) + "\n" + loginMethod + "\n" + loginPath +
		"\n" + hex.EncodeToString(digest[:]) + "\n" + fields.N + "\n")
	if !ed25519.Verify(classicalKey, signed, classicalSignature) || mldsa.Verify(pqKey, signed, pqSignature, nil) != nil {
		return "", ErrBadSignature
	}
	fingerprint := sha256.Sum256(append(classicalDer, pqDer...))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(fingerprint[:])), nil
}

func fresh(ts int64, now time.Time) bool {
	return ts >= now.Unix()-windowSeconds && ts <= now.Unix()+windowSeconds
}

func decodeJSON(encoded string, target any) error {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}
