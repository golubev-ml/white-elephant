package white_elephant_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
	"github.com/golubev-ml/white-elephant"
)

func Encode(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
func EncryptAES(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	plainBytes := []byte(plaintext)
	cfb := cipher.NewCFBEncrypter(block, key[1:17])
	cipherText := make([]byte, len(plainBytes))
	cfb.XORKeyStream(cipherText, plainBytes)
	return Encode(cipherText), nil
}

func TestWhiteElephantPositive1(t *testing.T) {
	cfg := white_elephant.CreateConfig()
	cfg.PartnerIDS = []string{"b157961d5da94f6b9e9fb34b57a9346b", "id2"}
	cfg.KeyLifeTime = 3600
	cfg.SecretKey = "thisis32bitlongpassphraseimusing"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := white_elephant.New(ctx, next, cfg, "pf-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	timestamp := time.Now().Add(time.Duration(-59) * time.Minute).UTC().Format(time.RFC3339)
	plaintext := cfg.PartnerIDS[0] + ":" + timestamp
	cypher, _ := EncryptAES([]byte(cfg.SecretKey), plaintext)
	full_url := fmt.Sprintf("http://localhost?partner_key=%s", url.QueryEscape(cypher))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full_url, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
	status := recorder.Result().StatusCode
	if 200 != status {
		t.Errorf("wrong status %d, expected 200", status)
	}
}

func TestWhiteElephantPositive2(t *testing.T) {
	cfg := white_elephant.CreateConfig()
	cfg.PartnerIDS = []string{"b157961d5da94f6b9e9fb34b57a9346b", "id2"}
	cfg.KeyLifeTime = 3600
	cfg.SecretKey = "thisis32bitlongpassphraseimusing"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := white_elephant.New(ctx, next, cfg, "pf-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	timestamp := time.Now().Add(time.Duration(-59) * time.Minute).UTC().Format(time.RFC3339)
	plaintext := cfg.PartnerIDS[0] + ":" + timestamp
	cypher, _ := EncryptAES([]byte(cfg.SecretKey), plaintext)
	full_url := "http://localhost"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full_url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Partner-Key", cypher)

	handler.ServeHTTP(recorder, req)
	status := recorder.Result().StatusCode
	if 200 != status {
		t.Errorf("wrong status %d, expected 200", status)
	}
}

func TestWhiteElephantPositive3(t *testing.T) {
	cfg := white_elephant.CreateConfig()
	cfg.PartnerIDS = []string{"b157961d5da94f6b9e9fb34b57a9346b", "id2"}
	cfg.KeyLifeTime = 3600
	cfg.SecretKey = "thisis32bitlongpassphraseimusing"
	cfg.WhiteList = []string{"abcccccc", "ddddddddd"}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := white_elephant.New(ctx, next, cfg, "pf-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	timestamp := time.Now().Add(time.Duration(-59) * time.Minute).UTC().Format(time.RFC3339)
	plaintext := cfg.PartnerIDS[0] + ":" + timestamp
	cypher, _ := EncryptAES([]byte("1hisis32bitlongpassphraseimusing"), plaintext)
	full_url := "http://localhost?param=ddddddddd"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full_url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Partner-Key", cypher)

	handler.ServeHTTP(recorder, req)
	status := recorder.Result().StatusCode
	if 200 != status {
		t.Errorf("wrong status %d, expected 200", status)
	}
}

func TestWhiteElephantNegative1(t *testing.T) {
	cfg := white_elephant.CreateConfig()
	cfg.PartnerIDS = []string{"b157961d5da94f6b9e9fb34b57a9346b", "id2"}
	cfg.KeyLifeTime = 3600
	cfg.SecretKey = "thisis32bitlongpassphraseimusing"
	cfg.WhiteList = []string{"abcccccc", "ddddddddd"}

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := white_elephant.New(ctx, next, cfg, "pf-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	timestamp := time.Now().Add(time.Duration(-59) * time.Minute).UTC().Format(time.RFC3339)
	plaintext := cfg.PartnerIDS[0] + ":" + timestamp
	cypher, _ := EncryptAES([]byte("1hisis32bitlongpassphraseimusing"), plaintext)
	full_url := "http://localhost?param=dddddddd"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full_url, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Partner-Key", cypher)

	handler.ServeHTTP(recorder, req)
	status := recorder.Result().StatusCode
	if 403 != status {
		t.Errorf("wrong status %d, expected 200", status)
	}
}
func TestWhiteElephantNegative2(t *testing.T) {
	cfg := white_elephant.CreateConfig()
	cfg.PartnerIDS = []string{"b157961d5da94f6b9e9fb34b57a9346b", "id2"}
	cfg.KeyLifeTime = 3600
	cfg.SecretKey = "thisis32bitlongpassphraseimusing"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := white_elephant.New(ctx, next, cfg, "pf-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	full_url := "http://localhost"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full_url, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)
	status := recorder.Result().StatusCode
	if 403 != status {
		t.Errorf("wrong status %d, expected 200", status)
	}
}
func TestWhiteElephantNegative3(t *testing.T) {
	cfg := white_elephant.CreateConfig()
	cfg.PartnerIDS = []string{"b157961d5da94f6b9e9fb34b57a9346b", "id2"}
	cfg.KeyLifeTime = 3600
	cfg.SecretKey = "thisis32bitlongpassphraseimusing"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := white_elephant.New(ctx, next, cfg, "pf-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	timestamp := time.Now().Add(time.Duration(-59) * time.Minute).UTC().Format(time.RFC3339)
	plaintext := cfg.PartnerIDS[0] + ":" + timestamp
	cypher, _ := EncryptAES([]byte("1hisis32bitlongpassphraseimusing"), plaintext)
	full_url := fmt.Sprintf("http://localhost?partner_key=%s", url.QueryEscape(cypher))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full_url, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
	status := recorder.Result().StatusCode
	if 403 != status {
		t.Errorf("wrong status %d, expected 200", status)
	}
}
func TestWhiteElephantNegative4(t *testing.T) {
	cfg := white_elephant.CreateConfig()
	cfg.PartnerIDS = []string{"b157961d5da94f6b9e9fb34b57a9346b", "id2"}
	cfg.KeyLifeTime = 3600
	cfg.SecretKey = "thisis32bitlongpassphraseimusing"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := white_elephant.New(ctx, next, cfg, "pf-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	timestamp := time.Now().Add(time.Duration(-59) * time.Minute).UTC().Format(time.RFC3339)
	plaintext := "id3:" + timestamp
	cypher, _ := EncryptAES([]byte(cfg.SecretKey), plaintext)
	full_url := fmt.Sprintf("http://localhost?partner_key=%s", url.QueryEscape(cypher))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full_url, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
	status := recorder.Result().StatusCode
	if 403 != status {
		t.Errorf("wrong status %d, expected 200", status)
	}
}
func TestWhiteElephantNegative5(t *testing.T) {
	cfg := white_elephant.CreateConfig()
	cfg.PartnerIDS = []string{"b157961d5da94f6b9e9fb34b57a9346b", "id2"}
	cfg.KeyLifeTime = 3600
	cfg.SecretKey = "thisis32bitlongpassphraseimusing"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := white_elephant.New(ctx, next, cfg, "pf-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	timestamp := time.Now().Add(time.Duration(-59) * time.Minute).UTC().Format(time.RFC1123)
	plaintext := cfg.PartnerIDS[0] + ":" + timestamp
	cypher, _ := EncryptAES([]byte(cfg.SecretKey), plaintext)
	full_url := fmt.Sprintf("http://localhost?partner_key=%s", url.QueryEscape(cypher))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full_url, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
	status := recorder.Result().StatusCode
	if 403 != status {
		t.Errorf("wrong status %d, expected 200", status)
	}
}
func TestWhiteElephantNegative6(t *testing.T) {
	cfg := white_elephant.CreateConfig()
	cfg.PartnerIDS = []string{"b157961d5da94f6b9e9fb34b57a9346b", "id2"}
	cfg.KeyLifeTime = 3600
	cfg.SecretKey = "thisis32bitlongpassphraseimusing"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := white_elephant.New(ctx, next, cfg, "pf-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	timestamp := time.Now().Add(time.Duration(-59) * time.Minute).Format(time.RFC3339)
	plaintext := cfg.PartnerIDS[0] + ":" + timestamp
	cypher, _ := EncryptAES([]byte(cfg.SecretKey), plaintext)
	full_url := fmt.Sprintf("http://localhost?partner_key=%s", url.QueryEscape(cypher))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full_url, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
	status := recorder.Result().StatusCode
	if 403 != status {
		t.Errorf("wrong status %d, expected 200", status)
	}
}
func TestWhiteElephantNegative7(t *testing.T) {
	cfg := white_elephant.CreateConfig()
	cfg.PartnerIDS = []string{"b157961d5da94f6b9e9fb34b57a9346b", "id2"}
	cfg.KeyLifeTime = 3600
	cfg.SecretKey = "thisis32bitlongpassphraseimusing"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := white_elephant.New(ctx, next, cfg, "pf-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	timestamp := time.Now().Add(time.Duration(2) * time.Minute).UTC().Format(time.RFC3339)
	plaintext := cfg.PartnerIDS[0] + ":" + timestamp
	cypher, _ := EncryptAES([]byte(cfg.SecretKey), plaintext)
	full_url := fmt.Sprintf("http://localhost?partner_key=%s", url.QueryEscape(cypher))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full_url, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
	status := recorder.Result().StatusCode
	if 403 != status {
		t.Errorf("wrong status %d, expected 200", status)
	}
}
func TestWhiteElephantNegative8(t *testing.T) {
	cfg := white_elephant.CreateConfig()
	cfg.PartnerIDS = []string{"b157961d5da94f6b9e9fb34b57a9346b", "id2"}
	cfg.KeyLifeTime = 3600
	cfg.SecretKey = "thisis32bitlongpassphraseimusing"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	handler, err := white_elephant.New(ctx, next, cfg, "pf-plugin")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	timestamp := time.Now().Add(time.Duration(-62) * time.Minute).UTC().Format(time.RFC3339)
	plaintext := cfg.PartnerIDS[0] + ":" + timestamp
	cypher, _ := EncryptAES([]byte(cfg.SecretKey), plaintext)
	full_url := fmt.Sprintf("http://localhost?partner_key=%s", url.QueryEscape(cypher))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full_url, nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
	status := recorder.Result().StatusCode
	if 403 != status {
		t.Errorf("wrong status %d, expected 200", status)
	}
}
