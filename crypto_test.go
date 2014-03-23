package ucenter

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"testing"
	"time"
)

func TestEncode(t *testing.T) {
	handler := NewCryptoHandler("abc", "def")

	va := make(map[string]interface{})
	va["abc"] = "def"
	va["a"] = "b"

	res, _ := handler.Encrypt(va)
	// fmt.Println(v["abc"])
	fmt.Println(res)

	m, _ := handler.Decrypt(res)
	fmt.Println("...%s", m["abc"])
	fmt.Println("...%s", m["a"])

}

func createKey() (encKey, hmacKey []byte) {
	encSha1 := sha1.New()
	encSha1.Write([]byte(time.Now().UTC().String()))
	encSha1.Write([]byte("-enc"))
	encKey = encSha1.Sum(nil)[:blockSize]

	hmacSha1 := sha1.New()
	hmacSha1.Write([]byte(time.Now().UTC().String()))
	hmacSha1.Write([]byte("-hmac"))
	hmacKey = hmacSha1.Sum(nil)[:blockSize]

	return
}

func TestRoundtrip(t *testing.T) {
	encKey, hmacKey := createKey()

	orig := map[string]interface{}{"a": 1, "b": "c", "d": 1.2}

	encoded, encodedHash, err := encodeMap(orig, encKey, hmacKey)
	if err != nil {
		t.Errorf("encodeCookie: %s", err)
		return
	}
	decoded, decodedHash, err := decodeMap(encoded, encKey, hmacKey)
	if err != nil {
		t.Errorf("decodeCookie: %s", err)
		return
	}

	if decoded == nil {
		t.Errorf("decoded map is null")
		return
	}

	if len(decoded) != 3 {
		t.Errorf("len was %d, expected 3", len(decoded))
		return
	}

	if !bytes.Equal(encodedHash, decodedHash) {
		t.Errorf("encoded & decoded gob hash mismatches: %s, %s",
			string(encodedHash), string(decodedHash))
	}

	for k, v := range orig {
		if decoded[k] != v {
			t.Errorf("expected decoded[%s] (%#v) == %#v", k,
				decoded[k], v)
		}
	}
}
