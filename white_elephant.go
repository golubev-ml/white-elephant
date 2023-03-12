package white_elephant

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	WhiteList   []string `json:"white_list,omitempty"`
	PartnerIDS  []string `json:"partner_ids,omitempty"`
	KeyLifeTime int      `json:"key_lifetime,omitempty"`
	SecretKey   string   `json:"secret_key,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		WhiteList:   make([]string, 0),
		PartnerIDS:  make([]string, 0),
		KeyLifeTime: 3600,
		SecretKey:   "thisis32bitlongpassphraseimusing",
	}
}

// WhiteElephant plugin.
type WhiteElephant struct {
	next         http.Handler
	name         string
	partner_ids  []string
	white_list   []string
	key_lifetime int
	secret_key   string
}

// New created a new WhiteElephant plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &WhiteElephant{
		next:         next,
		name:         name,
		white_list:   config.WhiteList,
		partner_ids:  config.PartnerIDS,
		key_lifetime: config.KeyLifeTime,
		secret_key:   config.SecretKey,
	}, nil
}

func Decode(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return data, nil
}
func DecryptAES(key []byte, ct string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}
	//os.Stdout.WriteString(ct + "\n")
	cipherText, err := Decode(ct)
	if err != nil {
		return "", err
	}
	cfb := cipher.NewCFBDecrypter(block, key[1:17])
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}
func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}
func (a *WhiteElephant) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// When URL matches one of the expressions from the list
	// just forrward the request to the next handler
	for _, re := range a.white_list {
		matched, _ := regexp.MatchString(re, req.URL.String())
		if matched {
			a.next.ServeHTTP(rw, req)
			return
		}
	}
	// get X-Partner-Key or partner_key
	// if both are missing reply with error
	x_partner_key := req.Header.Get("X-Partner-Key")
	partner_key := req.URL.Query().Get("partner_key")
	if x_partner_key == "" && partner_key == "" {
		os.Stdout.WriteString("error missing partner key\n")
		http.Error(rw, "err code 1001", http.StatusForbidden)
		return
	}
	// if one is missing prioritize partner_key
	// otherwise take X-Partner-Key
	// both already urldecoded here
	if partner_key == "" {
		partner_key = x_partner_key
	}

	// decrypt partner_key with secret_key with AES
	partner_key, err := DecryptAES([]byte(a.secret_key), partner_key)
	if err != nil {
		os.Stdout.WriteString("error decrypting partner_key\n")
		http.Error(rw, "err code 1002", http.StatusForbidden)
		return
	}
	// os.Stdout.WriteString(fmt.Sprintf("partner key is %s\n", partner_key))
	// parsing partner_key into parts
	// example
	// b157961d5da94f6b9e9fb34b57a9346b:2023-03-10T11:52:52.015572+00:00
	split_parts := strings.Split(partner_key, ":")
	id_part := split_parts[0]
	if !stringInSlice(id_part, a.partner_ids) {
		os.Stdout.WriteString("error partner id is not found\n")
		http.Error(rw, "err code 1003", http.StatusForbidden)
		return
	}
	time_part := strings.Join(split_parts[1:], ":")
	timestamp, err := time.Parse(time.RFC3339, time_part)
	if err != nil {
		os.Stdout.WriteString("cannot parse timestamp from partner_key\n")
		http.Error(rw, "err code 1004", http.StatusForbidden)
		return
	}
	_, offset := timestamp.Zone()
	if offset != 0 {
		os.Stdout.WriteString("partner_key timestamp's timezone is not UTC\n")
		http.Error(rw, "err code 1005", http.StatusForbidden)
		return
	}
	if time.Since(timestamp) < 0 {
		os.Stdout.WriteString("partner_key timestamp is from the future\n")
		http.Error(rw, "err code 1006", http.StatusForbidden)
		return
	}
	if time.Since(timestamp) > time.Duration(float64(a.key_lifetime)*float64(time.Second)) {
		os.Stdout.WriteString("partner_key is expired\n")
		http.Error(rw, "err code 1007", http.StatusForbidden)
		return
	}
	//os.Stdout.WriteString(timestamp.String() + "\n")
	//os.Stdout.WriteString(time.Now().Sub(timestamp).String() + "\n")
	a.next.ServeHTTP(rw, req)
}
