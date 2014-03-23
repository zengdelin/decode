package ucenter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/gob"
	"errors"
	"fmt"
	"hash"
	"io"
)

var (
	HashError = errors.New("Hash validation failed")
	LenError  = errors.New("Bad cookie length")
)

const blockSize = 16

type CryptoHandler struct {
	encKey  []byte
	hmacKey []byte
}

func NewCryptoHandler(encKey string, hmacKey string) *CryptoHandler {
	encHash := sha1.New()
	encHash.Write([]byte(encKey))
	encHash.Write([]byte("-encryption"))
	hmacHash := sha1.New()
	hmacHash.Write([]byte(hmacKey))
	hmacHash.Write([]byte("-hmac"))

	handler := CryptoHandler{}
	handler.encKey = encHash.Sum(nil)[:blockSize]
	handler.hmacKey = hmacHash.Sum(nil)[:blockSize]

	// encHash.Sum(nil)[:blockSize], hmacHash.Sum(nil)[:blockSize]
	return &handler

}

func (c *CryptoHandler) Encrypt(encMap map[string]interface{}) (string, []byte) {

	fmt.Println("------------------------>>>>>>>>>>>>>>>>>>")
	fmt.Println("encKey:%s   hmacKey:%s", c.encKey, c.hmacKey)
	encoded, gobHash, err := encodeMap(encMap, c.encKey, c.hmacKey)
	if err != nil {
		fmt.Println(err)
	}
	// return "nil", nil
	return encoded, gobHash
}

func (c *CryptoHandler) Decrypt(decStr string) (map[string]interface{}, []byte) {
	session, gobHash, err := decodeMap(decStr, c.encKey, c.hmacKey)
	if err != nil {
		return map[string]interface{}{}, nil
	}

	return session, gobHash
}

func encodeGob(obj interface{}) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	enc := gob.NewEncoder(buf)
	err := enc.Encode(obj)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

/**
 *
 *gob 反序列化
 *
 **/
func decodeGob(encoded []byte) (map[string]interface{}, error) {
	buf := bytes.NewBuffer(encoded)
	dec := gob.NewDecoder(buf)
	var out map[string]interface{}
	err := dec.Decode(&out)
	if err != nil {
		return nil, err
	}
	return out, nil
}

//
//   encrypted(salt + sessionData) + iv + hmac
//
func encode(block cipher.Block, hmac hash.Hash, data []byte) ([]byte, error) {

	buf := bytes.NewBuffer(nil)

	salt := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	buf.Write(salt)
	buf.Write(data)

	session := buf.Bytes()

	iv := make([]byte, block.BlockSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(session, session)

	buf.Write(iv)
	hmac.Write(buf.Bytes())
	buf.Write(hmac.Sum(nil))

	return buf.Bytes(), nil
}

/**
 *
 *cookie加密
 *
 **/
func encodeMap(content interface{}, encKey, hmacKey []byte) (string, []byte, error) {
	encodedGob, err := encodeGob(content)
	if err != nil {
		return "", nil, err
	}

	gobHash := sha1.New()
	gobHash.Write(encodedGob)

	aesCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return "", nil, err
	}

	hmacHash := hmac.New(sha256.New, hmacKey)

	sessionBytes, err := encode(aesCipher, hmacHash, encodedGob)
	if err != nil {
		return "", nil, err
	}

	return base64.StdEncoding.EncodeToString(sessionBytes), gobHash.Sum(nil), nil
}

/**
 *
 *解密函数
 *
 **/
func decode(block cipher.Block, hmac hash.Hash, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 2*block.BlockSize()+hmac.Size() {
		return nil, LenError
	}

	receivedHmac := ciphertext[len(ciphertext)-hmac.Size():]
	ciphertext = ciphertext[:len(ciphertext)-hmac.Size()]

	hmac.Write(ciphertext)
	if subtle.ConstantTimeCompare(hmac.Sum(nil), receivedHmac) != 1 {
		return nil, HashError
	}

	// split the iv and session bytes
	iv := ciphertext[len(ciphertext)-block.BlockSize():]
	session := ciphertext[:len(ciphertext)-block.BlockSize()]

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(session, session)

	// skip past the iv
	session = session[block.BlockSize():]

	return session, nil
}

/**
 *
 *cookie 解密
 *
 **/
func decodeMap(encoded string, encKey, hmacKey []byte) (map[string]interface{}, []byte, error) {
	sessionBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, err
	}
	aesCipher, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, err
	}

	hmacHash := hmac.New(sha256.New, hmacKey)
	gobBytes, err := decode(aesCipher, hmacHash, sessionBytes)
	if err != nil {
		return nil, nil, err
	}

	gobHash := sha1.New()
	gobHash.Write(gobBytes)

	session, err := decodeGob(gobBytes)
	if err != nil {
		return nil, nil, err
	}
	return session, gobHash.Sum(nil), nil
}
