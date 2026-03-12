package js

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
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
	"golang.org/x/crypto/hkdf"
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
		// HMAC computes HMAC with the given algorithm, returns hex string.
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
		// HMACBytes computes HMAC returning raw bytes (not hex).
		"HMACBytes": func(algo string, key, data interface{}) ([]byte, error) {
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
				return nil, fmt.Errorf("unsupported algorithm: %s", algo)
			}
			mac := hmac.New(h, k)
			mac.Write(d)
			return mac.Sum(nil), nil
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
		// AESGCMEncryptIV encrypts data using AES-GCM with a custom IV and optional AAD.
		// Required by Noise Protocol (counter-based IVs + hash chain as AAD).
		// Key: 16/24/32 bytes. IV: 12 bytes. AAD: optional additional authenticated data.
		"AESGCMEncryptIV": func(keyBytes, iv, plaintext, aad []byte) ([]byte, error) {
			block, err := aes.NewCipher(keyBytes)
			if err != nil {
				return nil, fmt.Errorf("AES key error: %v", err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return nil, err
			}
			if len(iv) != gcm.NonceSize() {
				return nil, fmt.Errorf("IV must be %d bytes, got %d", gcm.NonceSize(), len(iv))
			}
			var aadData []byte
			if len(aad) > 0 {
				aadData = aad
			}
			return gcm.Seal(nil, iv, plaintext, aadData), nil
		},
		// AESGCMDecryptIV decrypts data using AES-GCM with a custom IV and optional AAD.
		"AESGCMDecryptIV": func(keyBytes, iv, ciphertext, aad []byte) ([]byte, error) {
			block, err := aes.NewCipher(keyBytes)
			if err != nil {
				return nil, fmt.Errorf("AES key error: %v", err)
			}
			gcm, err := cipher.NewGCM(block)
			if err != nil {
				return nil, err
			}
			if len(iv) != gcm.NonceSize() {
				return nil, fmt.Errorf("IV must be %d bytes, got %d", gcm.NonceSize(), len(iv))
			}
			var aadData []byte
			if len(aad) > 0 {
				aadData = aad
			}
			return gcm.Open(nil, iv, ciphertext, aadData)
		},
		// AESCBCEncrypt encrypts data using AES-CBC with PKCS7 padding.
		// Key must be 16/24/32 bytes. IV must be 16 bytes (AES block size).
		"AESCBCEncrypt": func(keyBytes, iv, plaintext []byte) ([]byte, error) {
			block, err := aes.NewCipher(keyBytes)
			if err != nil {
				return nil, fmt.Errorf("AES key error: %v", err)
			}
			if len(iv) != aes.BlockSize {
				return nil, fmt.Errorf("IV must be %d bytes", aes.BlockSize)
			}
			// PKCS7 padding
			padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
			padded := make([]byte, len(plaintext)+padLen)
			copy(padded, plaintext)
			for i := len(plaintext); i < len(padded); i++ {
				padded[i] = byte(padLen)
			}
			ciphertext := make([]byte, len(padded))
			mode := cipher.NewCBCEncrypter(block, iv)
			mode.CryptBlocks(ciphertext, padded)
			return ciphertext, nil
		},
		// AESCBCDecrypt decrypts data using AES-CBC and removes PKCS7 padding.
		"AESCBCDecrypt": func(keyBytes, iv, ciphertext []byte) ([]byte, error) {
			block, err := aes.NewCipher(keyBytes)
			if err != nil {
				return nil, fmt.Errorf("AES key error: %v", err)
			}
			if len(iv) != aes.BlockSize {
				return nil, fmt.Errorf("IV must be %d bytes", aes.BlockSize)
			}
			if len(ciphertext)%aes.BlockSize != 0 {
				return nil, fmt.Errorf("ciphertext is not a multiple of block size")
			}
			plaintext := make([]byte, len(ciphertext))
			mode := cipher.NewCBCDecrypter(block, iv)
			mode.CryptBlocks(plaintext, ciphertext)
			// Remove PKCS7 padding
			if len(plaintext) == 0 {
				return plaintext, nil
			}
			padLen := int(plaintext[len(plaintext)-1])
			if padLen > aes.BlockSize || padLen == 0 {
				return nil, fmt.Errorf("invalid PKCS7 padding")
			}
			for i := len(plaintext) - padLen; i < len(plaintext); i++ {
				if plaintext[i] != byte(padLen) {
					return nil, fmt.Errorf("invalid PKCS7 padding")
				}
			}
			return plaintext[:len(plaintext)-padLen], nil
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
		// GenerateX25519 generates a new X25519 key pair (base64 encoded).
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
		// GenerateX25519Raw generates a new X25519 key pair returning raw bytes.
		"GenerateX25519Raw": func() (map[string]interface{}, error) {
			privKey := make([]byte, 32)
			_, err := rand.Read(privKey)
			if err != nil {
				return nil, err
			}
			pubKey, err := curve25519.X25519(privKey, curve25519.Basepoint)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"privateKey": privKey,
				"publicKey":  pubKey,
			}, nil
		},
		// X25519 computes a Curve25519 ECDH shared secret.
		// privateKey: 32-byte private key, publicKey: 32-byte peer public key.
		"X25519": func(privateKey, publicKey []byte) ([]byte, error) {
			if len(privateKey) != 32 {
				return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(privateKey))
			}
			if len(publicKey) != 32 {
				return nil, fmt.Errorf("public key must be 32 bytes, got %d", len(publicKey))
			}
			return curve25519.X25519(privateKey, publicKey)
		},
		// HKDF performs HKDF key derivation (extract + expand).
		// hash: "sha256", "sha512". Returns derived key of specified length.
		"HKDF": func(hashAlgo string, secret, salt, info interface{}, length int) ([]byte, error) {
			var h func() hash.Hash
			switch hashAlgo {
			case "sha256":
				h = sha256.New
			case "sha512":
				h = sha512.New
			case "sha1":
				h = sha1.New
			default:
				return nil, fmt.Errorf("unsupported hash: %s", hashAlgo)
			}
			s := cryptoToBytes(secret)
			var saltBytes []byte
			if salt != nil {
				saltBytes = cryptoToBytes(salt)
			}
			var infoBytes []byte
			if info != nil {
				infoBytes = cryptoToBytes(info)
			}
			reader := hkdf.New(h, s, saltBytes, infoBytes)
			derived := make([]byte, length)
			if _, err := io.ReadFull(reader, derived); err != nil {
				return nil, fmt.Errorf("HKDF failed: %v", err)
			}
			return derived, nil
		},
		// HKDFExtract performs only the HKDF extract step (PRK generation).
		"HKDFExtract": func(hashAlgo string, secret, salt interface{}) ([]byte, error) {
			var h func() hash.Hash
			switch hashAlgo {
			case "sha256":
				h = sha256.New
			case "sha512":
				h = sha512.New
			case "sha1":
				h = sha1.New
			default:
				return nil, fmt.Errorf("unsupported hash: %s", hashAlgo)
			}
			s := cryptoToBytes(secret)
			var saltBytes []byte
			if salt != nil {
				saltBytes = cryptoToBytes(salt)
			}
			return hkdf.Extract(h, s, saltBytes), nil
		},
		// HKDFExpand performs only the HKDF expand step.
		"HKDFExpand": func(hashAlgo string, prk, info interface{}, length int) ([]byte, error) {
			var h func() hash.Hash
			switch hashAlgo {
			case "sha256":
				h = sha256.New
			case "sha512":
				h = sha512.New
			case "sha1":
				h = sha1.New
			default:
				return nil, fmt.Errorf("unsupported hash: %s", hashAlgo)
			}
			prkBytes := cryptoToBytes(prk)
			var infoBytes []byte
			if info != nil {
				infoBytes = cryptoToBytes(info)
			}
			reader := hkdf.Expand(h, prkBytes, infoBytes)
			derived := make([]byte, length)
			if _, err := io.ReadFull(reader, derived); err != nil {
				return nil, fmt.Errorf("HKDF expand failed: %v", err)
			}
			return derived, nil
		},
		// Ed25519Generate generates a new Ed25519 signing key pair.
		// Returns { publicKey: []byte(32), privateKey: []byte(64) }
		"Ed25519Generate": func() (map[string]interface{}, error) {
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return nil, err
			}
			return map[string]interface{}{
				"publicKey":  []byte(pub),
				"privateKey": []byte(priv),
			}, nil
		},
		// Ed25519Sign signs a message with an Ed25519 private key (64 bytes).
		"Ed25519Sign": func(privateKey, message []byte) ([]byte, error) {
			if len(privateKey) != ed25519.PrivateKeySize {
				return nil, fmt.Errorf("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(privateKey))
			}
			return ed25519.Sign(ed25519.PrivateKey(privateKey), message), nil
		},
		// Ed25519Verify verifies an Ed25519 signature.
		"Ed25519Verify": func(publicKey, message, signature []byte) (bool, error) {
			if len(publicKey) != ed25519.PublicKeySize {
				return false, fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(publicKey))
			}
			return ed25519.Verify(ed25519.PublicKey(publicKey), message, signature), nil
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

// Ensure bytes import is used (for AES-CBC padding validation)
var _ = bytes.Compare
