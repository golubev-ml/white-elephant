package white_elephant

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/exp/slices"
)

// Config the plugin configuration.
// there is a problem with underscores in variable names
// https://groups.google.com/g/golang-nuts/c/OQSkN6QH-Cc
type Config struct {
	WhiteList   []string `json:"whitelist,omitempty"`
	PartnerIDs  []string `json:"partnerids,omitempty"`
	KeyLifeTime int      `json:"keylifetime,omitempty"`
	SecretKey   string   `json:"secretkey,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		WhiteList:   make([]string, 0),
		PartnerIDs:  make([]string, 0),
		KeyLifeTime: 3600,
		SecretKey:   "thisis32bitlongpassphraseimusing",
	}
}

// WhiteElephant plugin.
type WhiteElephant struct {
	next        http.Handler
	name        string
	partnerIDs  []string
	whiteList   []string
	keyLifeTime int
	secretKey   string
}

// New created a new WhiteElephant plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	fmt.Println("name is ", name)
	fmt.Println("whiteList is ", strings.Join(config.WhiteList, " "))
	fmt.Println("partnerIDs is ", strings.Join(config.PartnerIDs, " "))
	return &WhiteElephant{
		next:        next,
		name:        name,
		whiteList:   config.WhiteList,
		partnerIDs:  config.PartnerIDs,
		keyLifeTime: config.KeyLifeTime,
		secretKey:   config.SecretKey,
	}, nil
}

func DecryptAES(key []byte, ct string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("failed to create new cipher: %w", err)
	}
	//fmt.Println(ct)
	cipherText, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		return "", fmt.Errorf("failed to decode cipher text: %w", err)
	}
	cfb := cipher.NewCFBDecrypter(block, key[1:17])
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)
	return string(plainText), nil
}
func (a *WhiteElephant) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// When URL matches one of the expressions from the list
	// just forrward the request to the next handler
	for _, re := range a.whiteList {
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
		fmt.Println("error missing partner key")
		fmt.Println("either in partner_key or in X-Partner-Key")
		http.Error(rw, "err code 1001", http.StatusForbidden)
		return
	}
	// if one is missing prioritize partner_key
	// otherwise take X-Partner-Key
	// both already urldecoded here
	if partner_key == "" {
		partner_key = x_partner_key
	}

	// decrypt partner_key with secretKey with AES
	decrypted_partner_key, err := DecryptAES([]byte(a.secretKey), partner_key)
	if err != nil {
		fmt.Println("error decrypting partner_key")
		fmt.Println("partner_key is ", partner_key)
		http.Error(rw, "err code 1002", http.StatusForbidden)
		return
	}
	// fmt.Println(fmt.Sprintf("partner key is ", partner_key))
	// parsing partner_key into parts
	// example
	// b157961d5da94f6b9e9fb34b57a9346b:2023-03-10T11:52:52.015572+00:00
	split_parts := strings.Split(decrypted_partner_key, ":")
	id_part := split_parts[0]
	if !slices.Contains(a.partnerIDs, id_part) {
		fmt.Println("error partner id is not found")
		fmt.Println("partner id is ", id_part)
		fmt.Println("not in ", strings.Join(a.partnerIDs, " "))
		http.Error(rw, "err code 1003", http.StatusForbidden)
		return
	}
	time_part := strings.Join(split_parts[1:], ":")
	timestamp, err := time.Parse(time.RFC3339, time_part)
	if err != nil {
		fmt.Println("cannot parse timestamp from partner_key")
		fmt.Println("time_part is ", time_part)
		http.Error(rw, "err code 1004", http.StatusForbidden)
		return
	}
	_, offset := timestamp.Zone()
	if offset != 0 {
		fmt.Println("partner_key timestamp's timezone is not UTC")
		fmt.Println("time_part is ", time_part)
		http.Error(rw, "err code 1005", http.StatusForbidden)
		return
	}
	nowTime := time.Now()
	if nowTime.Before(timestamp) {
		fmt.Println("partner_key timestamp is from the future")
		fmt.Println("time_part is ", time_part)
		http.Error(rw, "err code 1006", http.StatusForbidden)
		return
	}
	if nowTime.Sub(timestamp) > time.Duration(a.keyLifeTime)*time.Second {
		fmt.Println("partner_key is expired")
		fmt.Println("time_part is ", time_part)
		http.Error(rw, "err code 1007", http.StatusForbidden)
		return
	}
	//fmt.Println(timestamp.String())
	//fmt.Println(time.Now().Sub(timestamp).String())
	a.next.ServeHTTP(rw, req)
}
