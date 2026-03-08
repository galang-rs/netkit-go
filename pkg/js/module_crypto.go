package js

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/curve25519"
)

// RegisterCryptoModule injects ctx.Crypto into the JS context.
func RegisterCryptoModule(jsCtx map[string]interface{}) {
	jsCtx["Crypto"] = map[string]interface{}{
		// Base64Encode encodes bytes to base64 string.
		"Base64Encode": func(data []byte) string {
			return base64.StdEncoding.EncodeToString(data)
		},
		// Base64Decode decodes a base64 string to bytes.
		"Base64Decode": func(s string) ([]byte, error) {
			return base64.StdEncoding.DecodeString(s)
		},
		// Base64URLEncode encodes bytes to URL-safe base64.
		"Base64URLEncode": func(data []byte) string {
			return base64.URLEncoding.EncodeToString(data)
		},
		// Base64URLDecode decodes URL-safe base64.
		"Base64URLDecode": func(s string) ([]byte, error) {
			return base64.URLEncoding.DecodeString(s)
		},
		// HexEncode converts bytes to hex string.
		"HexEncode": func(data []byte) string {
			return hex.EncodeToString(data)
		},
		// HexDecode converts hex string to bytes.
		"HexDecode": func(s string) ([]byte, error) {
			return hex.DecodeString(s)
		},
		// SHA256 computes SHA-256 hash returning hex string.
		"SHA256": func(data interface{}) string {
			b := cryptoToBytes(data)
			h := sha256.Sum256(b)
			return hex.EncodeToString(h[:])
		},
		// SHA256Bytes computes SHA-256 hash returning raw bytes.
		"SHA256Bytes": func(data interface{}) []byte {
			b := cryptoToBytes(data)
			h := sha256.Sum256(b)
			return h[:]
		},
		// SHA1 computes SHA-1 hash.
		"SHA1": func(data interface{}) string {
			b := cryptoToBytes(data)
			h := sha1.Sum(b)
			return hex.EncodeToString(h[:])
		},
		// SHA512 computes SHA-512 hash.
		"SHA512": func(data interface{}) string {
			b := cryptoToBytes(data)
			h := sha512.Sum512(b)
			return hex.EncodeToString(h[:])
		},
		// MD5 computes MD5 hash.
		"MD5": func(data interface{}) string {
			b := cryptoToBytes(data)
			h := md5.Sum(b)
			return hex.EncodeToString(h[:])
		},
		// HMAC computes HMAC with the given algorithm.
		// algo: "sha256", "sha1", "sha512", "md5"
		"HMAC": func(algo string, key, data interface{}) (string, error) {
			k := cryptoToBytes(key)
			d := cryptoToBytes(data)
			var h func() hash.Hash
			switch algo {
			case "sha256":
				h = sha256.New
			case "sha1":
				h = sha1.New
			case "sha512":
				h = sha512.New
			case "md5":
				h = md5.New
			default:
				return "", fmt.Errorf("unsupported algorithm: %s", algo)
			}
			mac := hmac.New(h, k)
			mac.Write(d)
			return hex.EncodeToString(mac.Sum(nil)), nil
		},
		// XOR applies XOR with key (repeating) on data.
		"XOR": func(data, key []byte) []byte {
			if len(key) == 0 {
				return data
			}
			result := make([]byte, len(data))
			for i := range data {
				result[i] = data[i] ^ key[i%len(key)]
			}
			return result
		},
		// AESEncrypt encrypts data using AES-GCM. Key must be 16/24/32 bytes.
		"AESEncrypt": func(keyBytes, plaintext []byte) (map[string]interface{}, error) {
			block, err := aes.NewCipher(keyBytes)
			if err != nil {
				return nil, fmt.Errorf("AES key error: %v", err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return nil, err
			}
			nonce := make([]byte, gcm.NonceSize())
			if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
				return nil, err
			}
			ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
			return map[string]interface{}{
				"ciphertext": ciphertext,
				"nonce":      nonce,
			}, nil
		},
		// AESDecrypt decrypts data using AES-GCM.
		"AESDecrypt": func(keyBytes, nonce, ciphertext []byte) ([]byte, error) {
			block, err := aes.NewCipher(keyBytes)
			if err != nil {
				return nil, fmt.Errorf("AES key error: %v", err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return nil, err
			}
			return gcm.Open(nil, nonce, ciphertext, nil)
		},
		// RandomBytes generates n cryptographically-secure random bytes.
		"RandomBytes": func(n int) ([]byte, error) {
			b := make([]byte, n)
			_, err := rand.Read(b)
			return b, err
		},
		// RandomHex generates n random bytes as hex string.
		"RandomHex": func(n int) (string, error) {
			b := make([]byte, n)
			_, err := rand.Read(b)
			if err != nil {
				return "", err
			}
			return hex.EncodeToString(b), nil
		},
		// GenerateX25519 generates a new X25519 key pair for WireGuard/WARP.
		"GenerateX25519": func() (map[string]interface{}, error) {
			privKey := make([]byte, 32)
			_, err := rand.Read(privKey)
			if err != nil {
				return nil, err
			}
			// WireGuard private key clamping
			privKey[0] &= 248
			privKey[31] = (privKey[31] & 127) | 64

			pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
			if err != nil {
				return nil, err
			}

			return map[string]interface{}{
				"privateKey": base64.StdEncoding.EncodeToString(privKey),
				"publicKey":  base64.StdEncoding.EncodeToString(pubKey),
			}, nil
		},
	}
}

func cryptoToBytes(v interface{}) []byte {
	switch val := v.(type) {
	case string:
		return []byte(val)
	case []byte:
		return val
	default:
		return []byte(fmt.Sprintf("%v", v))
	}
}
