package js

import (
	"encoding/hex"
	"testing"
)

func TestRegisterCryptoModule_NotPanic(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto, ok := jsCtx["Crypto"]
	if !ok {
		t.Fatal("Crypto module should be registered")
	}
	cryptoMap, ok := crypto.(map[string]interface{})
	if !ok {
		t.Fatal("Crypto should be a map")
	}
	expectedFuncs := []string{
		"Base64Encode", "Base64Decode",
		"Base64URLEncode", "Base64URLDecode",
		"HexEncode", "HexDecode",
		"SHA256", "SHA256Bytes", "SHA1", "SHA512", "MD5",
		"HMAC", "XOR",
		"AESEncrypt", "AESDecrypt",
		"RandomBytes", "RandomHex",
	}
	for _, fn := range expectedFuncs {
		if _, exists := cryptoMap[fn]; !exists {
			t.Errorf("missing function: %s", fn)
		}
	}
}

func TestCrypto_Base64(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	encode := crypto["Base64Encode"].(func([]byte) string)
	decode := crypto["Base64Decode"].(func(string) ([]byte, error))

	encoded := encode([]byte("Hello, NetKit!"))
	decoded, err := decode(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if string(decoded) != "Hello, NetKit!" {
		t.Errorf("round-trip failed: got '%s'", decoded)
	}
}

func TestCrypto_Base64URL(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	encode := crypto["Base64URLEncode"].(func([]byte) string)
	decode := crypto["Base64URLDecode"].(func(string) ([]byte, error))

	encoded := encode([]byte("URL safe: /+= test"))
	decoded, err := decode(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if string(decoded) != "URL safe: /+= test" {
		t.Error("URL-safe base64 round-trip failed")
	}
}

func TestCrypto_HexEncodeDecode(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	encode := crypto["HexEncode"].(func([]byte) string)
	decode := crypto["HexDecode"].(func(string) ([]byte, error))

	input := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	encoded := encode(input)
	if encoded != "deadbeef" {
		t.Errorf("expected 'deadbeef', got '%s'", encoded)
	}
	decoded, err := decode(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if hex.EncodeToString(decoded) != "deadbeef" {
		t.Error("hex round-trip failed")
	}
}

func TestCrypto_SHA256(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	sha256 := crypto["SHA256"].(func(interface{}) string)

	hash := sha256("hello")
	if len(hash) != 64 { // SHA-256 = 32 bytes = 64 hex chars
		t.Errorf("expected 64 hex chars, got %d", len(hash))
	}
	// Known hash for "hello"
	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if hash != expected {
		t.Errorf("SHA256('hello') = '%s', want '%s'", hash, expected)
	}
}

func TestCrypto_SHA256Bytes(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	sha256Bytes := crypto["SHA256Bytes"].(func(interface{}) []byte)
	hash := sha256Bytes("hello")
	if len(hash) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(hash))
	}
}

func TestCrypto_SHA1(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	sha1 := crypto["SHA1"].(func(interface{}) string)
	hash := sha1("hello")
	expected := "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
	if hash != expected {
		t.Errorf("SHA1('hello') = '%s', want '%s'", hash, expected)
	}
}

func TestCrypto_SHA512(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	sha512 := crypto["SHA512"].(func(interface{}) string)
	hash := sha512("hello")
	if len(hash) != 128 { // SHA-512 = 64 bytes = 128 hex chars
		t.Errorf("expected 128 hex chars, got %d", len(hash))
	}
}

func TestCrypto_MD5(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	md5 := crypto["MD5"].(func(interface{}) string)
	hash := md5("hello")
	expected := "5d41402abc4b2a76b9719d911017c592"
	if hash != expected {
		t.Errorf("MD5('hello') = '%s', want '%s'", hash, expected)
	}
}

func TestCrypto_HMAC(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	hmacFn := crypto["HMAC"].(func(string, interface{}, interface{}) (string, error))
	result, err := hmacFn("sha256", "secret_key", "message")
	if err != nil {
		t.Fatalf("HMAC error: %v", err)
	}
	if len(result) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(result))
	}
}

func TestCrypto_HMAC_InvalidAlgo(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	hmacFn := crypto["HMAC"].(func(string, interface{}, interface{}) (string, error))
	_, err := hmacFn("invalid", "key", "data")
	if err == nil {
		t.Error("should error for invalid algorithm")
	}
}

func TestCrypto_XOR(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	xor := crypto["XOR"].(func([]byte, []byte) []byte)

	data := []byte("hello")
	key := []byte{0xFF}
	encrypted := xor(data, key)
	decrypted := xor(encrypted, key)

	if string(decrypted) != "hello" {
		t.Error("XOR should be reversible")
	}
}

func TestCrypto_XOR_EmptyKey(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	xor := crypto["XOR"].(func([]byte, []byte) []byte)
	result := xor([]byte("hello"), []byte{})
	if string(result) != "hello" {
		t.Error("XOR with empty key should return original data")
	}
}

func TestCrypto_AES_EncryptDecrypt(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	encrypt := crypto["AESEncrypt"].(func([]byte, []byte) (map[string]interface{}, error))
	decrypt := crypto["AESDecrypt"].(func([]byte, []byte, []byte) ([]byte, error))

	key := make([]byte, 32) // AES-256
	copy(key, []byte("my-super-secret-key-32-bytes!!"))

	plaintext := []byte("Sensitive data for NetKit")
	result, err := encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt error: %v", err)
	}

	ciphertext := result["ciphertext"].([]byte)
	nonce := result["nonce"].([]byte)

	decrypted, err := decrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("decrypt error: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Error("AES round-trip failed")
	}
}

func TestCrypto_AES_InvalidKey(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	encrypt := crypto["AESEncrypt"].(func([]byte, []byte) (map[string]interface{}, error))
	_, err := encrypt([]byte("short"), []byte("data"))
	if err == nil {
		t.Error("should error with invalid key size")
	}
}

func TestCrypto_RandomBytes(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	randomBytes := crypto["RandomBytes"].(func(int) ([]byte, error))
	b, err := randomBytes(32)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(b))
	}
}

func TestCrypto_RandomHex(t *testing.T) {
	jsCtx := make(map[string]interface{})
	RegisterCryptoModule(jsCtx)
	crypto := jsCtx["Crypto"].(map[string]interface{})

	randomHex := crypto["RandomHex"].(func(int) (string, error))
	h, err := randomHex(16)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if len(h) != 32 { // 16 bytes = 32 hex chars
		t.Errorf("expected 32 hex chars, got %d", len(h))
	}
}

func TestCryptoToBytes_String(t *testing.T) {
	result := cryptoToBytes("hello")
	if string(result) != "hello" {
		t.Error("string conversion failed")
	}
}

func TestCryptoToBytes_Bytes(t *testing.T) {
	input := []byte{1, 2, 3}
	result := cryptoToBytes(input)
	if len(result) != 3 {
		t.Error("byte conversion failed")
	}
}

func TestCryptoToBytes_Other(t *testing.T) {
	result := cryptoToBytes(42)
	if string(result) != "42" {
		t.Errorf("expected '42', got '%s'", result)
	}
}
