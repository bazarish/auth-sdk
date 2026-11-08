package bazarishauth

import (
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
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

	"golang.org/x/crypto/chacha20poly1305"
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
	challengePrefix  = "bazarish://sign?c="
	callbackMax      = 256
	callbackScheme   = "http://"
	b32Suffix        = ".b32.i2p"
	b32LabelChars    = 52
	b33LabelChars    = 56
	callbackMarks    = "-._~!$&'()*+,;=:@/?%"
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
	ErrInvalidCallback    = errors.New("bazarishauth: the callback is not an http path on a .b32.i2p address")
	ErrShortSecret        = errors.New("bazarishauth: the secret is shorter than 32 bytes")
	ErrMalformedChallenge = errors.New("bazarishauth: this is not a login challenge")
	ErrForeignConsumer    = errors.New("bazarishauth: the challenge names another consumer")
	ErrExpired            = errors.New("bazarishauth: expired")
	ErrUnknownChallenge   = errors.New("bazarishauth: the challenge was not issued here")
	ErrMalformedBlob      = errors.New("bazarishauth: this is not a login signature")
	ErrWrongKeyType       = errors.New("bazarishauth: a key of the wrong type")
	ErrBadSignature       = errors.New("bazarishauth: the signature does not verify")
	ErrAlreadyUsed        = errors.New("bazarishauth: the challenge has already been used")
	ErrMalformedAnswer    = errors.New("bazarishauth: this is not an answer sealed under this key")
	ErrKeySize            = errors.New("bazarishauth: a key is 32 bytes")
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
	return v.issue(now, "")
}

// IssueWithCallback names where the client may send the blob itself.
func (v *Verifier) IssueWithCallback(now time.Time, callback string) (string, error) {
	if !callbackUsable(callback) {
		return "", ErrInvalidCallback
	}
	return v.issue(now, callback)
}

func (v *Verifier) issue(now time.Time, callback string) (string, error) {
	raw := make([]byte, nonceBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(raw)
	ts := now.Unix()
	head := `{`
	if callback != "" {
		head += `"callback":"` + callback + `",`
	}
	challenge := head + `"consumer":` + v.canonical + `,"nonce":"` + nonce + `","tag":"` + v.tag(nonce, ts, callback) +
		`","ts":` + strconv.FormatInt(ts, 10) + `,"v":` + strconv.Itoa(challengeVersion) + `}`
	return challengePrefix + base64.RawURLEncoding.EncodeToString([]byte(challenge)), nil
}

func (v *Verifier) Verify(challenge, blob string, now time.Time) (string, error) {
	var envelope struct {
		V        int       `json:"v"`
		Nonce    string    `json:"nonce"`
		Ts       int64     `json:"ts"`
		Consumer *Consumer `json:"consumer"`
		Tag      string    `json:"tag"`
		Callback string    `json:"callback"`
	}
	if decodeChallenge(challenge, &envelope) != nil || envelope.V != challengeVersion ||
		envelope.Consumer == nil || !envelope.Consumer.usable() {
		return "", ErrMalformedChallenge
	}
	if envelope.Consumer.canonical() != v.canonical {
		return "", ErrForeignConsumer
	}
	if !fresh(envelope.Ts, now) {
		return "", ErrExpired
	}
	if !hmac.Equal([]byte(envelope.Tag), []byte(v.tag(envelope.Nonce, envelope.Ts, envelope.Callback))) {
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

func (v *Verifier) tag(nonce string, ts int64, callback string) string {
	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(nonce + "\n" + strconv.FormatInt(ts, 10) + "\n" + v.canonical + "\n" + callback))
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

func callbackUsable(callback string) bool {
	rest, found := strings.CutPrefix(callback, callbackScheme)
	if !found || len(callback) > callbackMax {
		return false
	}
	host, path, found := strings.Cut(rest, "/")
	if !found || !isB32Host(host) {
		return false
	}
	for _, c := range path {
		if !(c < utf8.RuneSelf && (isAlnum(byte(c)) || strings.ContainsRune(callbackMarks, c))) {
			return false
		}
	}
	return true
}

func isB32Host(host string) bool {
	label, found := strings.CutSuffix(host, b32Suffix)
	if !found || (len(label) != b32LabelChars && len(label) != b33LabelChars) {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !(c >= 'a' && c <= 'z') && !(c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func decodeChallenge(challenge string, target any) error {
	encoded, found := strings.CutPrefix(challenge, challengePrefix)
	if !found || encoded == "" {
		return ErrMalformedChallenge
	}
	for i := 0; i < len(encoded); i++ {
		if c := encoded[i]; !isAlnum(c) && c != '-' && c != '_' {
			return ErrMalformedChallenge
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}

func decodeJSON(encoded string, target any) error {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, target)
}

// SignInWithKey.md, "The key".
const (
	keyBytes       = 32
	keyField       = "&key="
	challengeLabel = "bazarish sign-in challenge v1"
	answerLabel    = "bazarish sign-in answer v1"
)

// NewKey makes the key one challenge's exchanges over I2P are sealed under.
func NewKey() ([]byte, error) {
	key := make([]byte, keyBytes)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// WithKey appends the key to a link that hands a challenge over I2P.
func WithKey(link string, key []byte) (string, error) {
	if len(key) != keyBytes {
		return "", ErrKeySize
	}
	return link + keyField + base64.RawURLEncoding.EncodeToString(key), nil
}

// SealChallenge is the body of the answer to GET on an at= path.
func SealChallenge(key []byte, challenge string) ([]byte, error) {
	aead, err := sealing(key, challengeLabel)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, []byte(challenge), nil), nil
}

type sealedAnswer struct {
	Nonce  string `json:"nonce"`
	Sealed string `json:"sealed"`
}

// AnswerNonce names the challenge a callback's body answers, so the site can find its key.
func AnswerNonce(body []byte) (string, error) {
	outer, err := answerOuter(body)
	if err != nil {
		return "", err
	}
	return outer.Nonce, nil
}

// OpenAnswer opens a callback's body; pass what it returns to Verify.
func OpenAnswer(key, body []byte) (challenge, blob string, err error) {
	outer, err := answerOuter(body)
	if err != nil {
		return "", "", err
	}
	sealed, err := base64.StdEncoding.DecodeString(outer.Sealed)
	if err != nil {
		return "", "", ErrMalformedAnswer
	}
	aead, err := sealing(key, answerLabel)
	if err != nil {
		return "", "", err
	}
	if len(sealed) < aead.NonceSize()+aead.Overhead() {
		return "", "", ErrMalformedAnswer
	}
	opened, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], nil)
	if err != nil {
		return "", "", ErrMalformedAnswer
	}
	var inner struct {
		Challenge *string `json:"challenge"`
		Blob      *string `json:"blob"`
	}
	if json.Unmarshal(opened, &inner) != nil || inner.Challenge == nil || inner.Blob == nil {
		return "", "", ErrMalformedAnswer
	}
	var envelope struct {
		Nonce string `json:"nonce"`
	}
	if decodeChallenge(*inner.Challenge, &envelope) != nil || envelope.Nonce != outer.Nonce {
		return "", "", ErrMalformedAnswer
	}
	return *inner.Challenge, *inner.Blob, nil
}

func answerOuter(body []byte) (sealedAnswer, error) {
	var outer sealedAnswer
	if json.Unmarshal(body, &outer) != nil || outer.Nonce == "" || outer.Sealed == "" {
		return sealedAnswer{}, ErrMalformedAnswer
	}
	return outer, nil
}

func sealing(key []byte, label string) (cipher.AEAD, error) {
	if len(key) != keyBytes {
		return nil, ErrKeySize
	}
	derived, err := hkdf.Key(sha256.New, key, nil, label, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(derived)
}
