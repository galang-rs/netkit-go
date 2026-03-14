package dom

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"strings"

	"github.com/dop251/goja"
)

// ── Helpers ──────────────────────────────────────────────────────────────

// extractAlgorithm extracts the algorithm name (upper-cased) and the full
// parameter map from a JS algorithm argument (string or {name: "...", ...}).
func extractAlgorithm(vm *goja.Runtime, val goja.Value) (string, map[string]interface{}) {
	if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
		return "", nil
	}
	exported := val.Export()
	switch v := exported.(type) {
	case string:
		return strings.ToUpper(v), nil
	case map[string]interface{}:
		if n, ok := v["name"].(string); ok {
			return strings.ToUpper(n), v
		}
	}
	return val.String(), nil
}

// extractCryptoBytes extracts raw bytes from a JS typed array, ArrayBuffer,
// or array-like value.
func extractCryptoBytes(vm *goja.Runtime, val goja.Value) ([]byte, error) {
	if val == nil || goja.IsUndefined(val) || goja.IsNull(val) {
		return nil, fmt.Errorf("data is null or undefined")
	}
	exported := val.Export()
	switch v := exported.(type) {
	case goja.ArrayBuffer:
		return v.Bytes(), nil
	case []byte:
		return v, nil
	}
	// Fallback: try reading .buffer (DataView / typed array wrapper) or
	// indexed access.
	obj := val.ToObject(vm)
	if obj != nil {
		bufVal := obj.Get("buffer")
		if bufVal != nil && !goja.IsUndefined(bufVal) {
			if ab, ok := bufVal.Export().(goja.ArrayBuffer); ok {
				return ab.Bytes(), nil
			}
		}
		lengthVal := obj.Get("length")
		if lengthVal != nil && !goja.IsUndefined(lengthVal) {
			n := int(lengthVal.ToInteger())
			result := make([]byte, n)
			for i := 0; i < n; i++ {
				v := obj.Get(fmt.Sprintf("%d", i))
				if v != nil {
					result[i] = byte(v.ToInteger())
				}
			}
			return result, nil
		}
	}
	return nil, fmt.Errorf("unsupported data type for crypto: %T", exported)
}

// extractBytesFromAlgParam extracts []byte from an algorithm sub-parameter
// (e.g. "iv", "counter", "salt") that may be passed as typed array or buffer.
func extractBytesFromAlgParam(vm *goja.Runtime, params map[string]interface{}, key string) ([]byte, error) {
	raw, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("missing algorithm parameter: %s", key)
	}
	switch v := raw.(type) {
	case goja.ArrayBuffer:
		return v.Bytes(), nil
	case []byte:
		return v, nil
	}
	// It might be a goja object that was not exported fully. Wrap back and try.
	return extractCryptoBytes(vm, vm.ToValue(raw))
}

// getHashFunc returns the hash constructor and digest size for a given algorithm name.
func getHashFunc(name string) (func() hash.Hash, int, error) {
	switch strings.ToUpper(name) {
	case "SHA-1":
		return sha1.New, sha1.Size, nil
	case "SHA-256":
		return sha256.New, sha256.Size, nil
	case "SHA-384":
		return sha512.New384, 48, nil
	case "SHA-512":
		return sha512.New, sha512.Size, nil
	default:
		return nil, 0, fmt.Errorf("unsupported hash: %s", name)
	}
}

// resolveHashName resolves the hash from algorithm params.  The "hash" field
// can be a plain string ("SHA-256") or an object ({name: "SHA-256"}).
func resolveHashName(params map[string]interface{}) string {
	if params == nil {
		return "SHA-256"
	}
	h, ok := params["hash"]
	if !ok {
		return "SHA-256"
	}
	switch v := h.(type) {
	case string:
		return strings.ToUpper(v)
	case map[string]interface{}:
		if n, ok := v["name"].(string); ok {
			return strings.ToUpper(n)
		}
	}
	return "SHA-256"
}

// newCryptoKey builds a JS CryptoKey-like object.
func newCryptoKey(vm *goja.Runtime, keyType string, extractable bool, algorithm map[string]interface{}, usages []string, rawKey []byte) *goja.Object {
	obj := vm.NewObject()
	obj.Set("type", keyType)
	obj.Set("extractable", extractable)
	obj.Set("algorithm", algorithm)
	obj.Set("usages", usages)
	obj.Set("__rawKey__", rawKey)
	return obj
}

// extractRawKey pulls the raw key bytes out of a CryptoKey JS object.
func extractRawKey(vm *goja.Runtime, val goja.Value) ([]byte, error) {
	obj := val.ToObject(vm)
	if obj == nil {
		return nil, fmt.Errorf("invalid CryptoKey")
	}
	raw := obj.Get("__rawKey__")
	if raw == nil || goja.IsUndefined(raw) {
		return nil, fmt.Errorf("invalid CryptoKey: missing raw key data")
	}
	exported := raw.Export()
	switch v := exported.(type) {
	case []byte:
		return v, nil
	case goja.ArrayBuffer:
		return v.Bytes(), nil
	}
	return nil, fmt.Errorf("invalid key data type: %T", exported)
}

// toIntParam safely reads an int from algorithm params.
func toIntParam(params map[string]interface{}, key string, fallback int) int {
	v, ok := params[key]
	if !ok {
		return fallback
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return fallback
}

// toStringSlice converts an interface{} (JS array of strings) to []string.
func toStringSlice(v interface{}) []string {
	switch arr := v.(type) {
	case []interface{}:
		out := make([]string, len(arr))
		for i, s := range arr {
			out[i] = fmt.Sprintf("%v", s)
		}
		return out
	case []string:
		return arr
	}
	return nil
}

// ── PKCS7 padding for AES-CBC ────────────────────────────────────────────

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(data, pad...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	for _, b := range data[len(data)-padding:] {
		if int(b) != padding {
			return nil, fmt.Errorf("invalid padding byte")
		}
	}
	return data[:len(data)-padding], nil
}

// ── PBKDF2 (inline, no external dependency) ──────────────────────────────

func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	mac := hmac.New(h, password)
	hashLen := mac.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	var dk []byte
	for block := 1; block <= numBlocks; block++ {
		mac.Reset()
		mac.Write(salt)
		mac.Write([]byte{byte(block >> 24), byte(block >> 16), byte(block >> 8), byte(block)})
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// ── CreateSubtleCrypto ───────────────────────────────────────────────────

// CreateSubtleCrypto builds the crypto.subtle object with real crypto
// implementations backed by Go's standard library.
func CreateSubtleCrypto(vm *goja.Runtime) map[string]interface{} {
	return map[string]interface{}{
		// ── digest(algorithm, data) → Promise<ArrayBuffer> ──
		"digest": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 2 {
				reject(vm.ToValue("TypeError: 2 arguments required"))
				return vm.ToValue(promise)
			}
			algName, _ := extractAlgorithm(vm, call.Arguments[0])
			data, err := extractCryptoBytes(vm, call.Arguments[1])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("TypeError: %v", err)))
				return vm.ToValue(promise)
			}
			hashFn, _, hashErr := getHashFunc(algName)
			if hashErr != nil {
				reject(vm.ToValue(fmt.Sprintf("NotSupportedError: %v", hashErr)))
				return vm.ToValue(promise)
			}
			h := hashFn()
			h.Write(data)
			resolve(vm.ToValue(vm.NewArrayBuffer(h.Sum(nil))))
			return vm.ToValue(promise)
		},

		// ── encrypt(algorithm, key, data) → Promise<ArrayBuffer> ──
		"encrypt": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 3 {
				reject(vm.ToValue("TypeError: 3 arguments required"))
				return vm.ToValue(promise)
			}
			algName, algParams := extractAlgorithm(vm, call.Arguments[0])
			keyBytes, err := extractRawKey(vm, call.Arguments[1])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("InvalidAccessError: %v", err)))
				return vm.ToValue(promise)
			}
			plaintext, err := extractCryptoBytes(vm, call.Arguments[2])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("TypeError: %v", err)))
				return vm.ToValue(promise)
			}
			result, encErr := doEncrypt(vm, algName, algParams, keyBytes, plaintext)
			if encErr != nil {
				reject(vm.ToValue(fmt.Sprintf("OperationError: %v", encErr)))
				return vm.ToValue(promise)
			}
			resolve(vm.ToValue(vm.NewArrayBuffer(result)))
			return vm.ToValue(promise)
		},

		// ── decrypt(algorithm, key, data) → Promise<ArrayBuffer> ──
		"decrypt": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 3 {
				reject(vm.ToValue("TypeError: 3 arguments required"))
				return vm.ToValue(promise)
			}
			algName, algParams := extractAlgorithm(vm, call.Arguments[0])
			keyBytes, err := extractRawKey(vm, call.Arguments[1])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("InvalidAccessError: %v", err)))
				return vm.ToValue(promise)
			}
			ciphertext, err := extractCryptoBytes(vm, call.Arguments[2])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("TypeError: %v", err)))
				return vm.ToValue(promise)
			}
			result, decErr := doDecrypt(vm, algName, algParams, keyBytes, ciphertext)
			if decErr != nil {
				reject(vm.ToValue(fmt.Sprintf("OperationError: %v", decErr)))
				return vm.ToValue(promise)
			}
			resolve(vm.ToValue(vm.NewArrayBuffer(result)))
			return vm.ToValue(promise)
		},

		// ── sign(algorithm, key, data) → Promise<ArrayBuffer> ──
		"sign": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 3 {
				reject(vm.ToValue("TypeError: 3 arguments required"))
				return vm.ToValue(promise)
			}
			algName, algParams := extractAlgorithm(vm, call.Arguments[0])
			keyBytes, err := extractRawKey(vm, call.Arguments[1])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("InvalidAccessError: %v", err)))
				return vm.ToValue(promise)
			}
			data, err := extractCryptoBytes(vm, call.Arguments[2])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("TypeError: %v", err)))
				return vm.ToValue(promise)
			}
			result, signErr := doSign(algName, algParams, keyBytes, data)
			if signErr != nil {
				reject(vm.ToValue(fmt.Sprintf("NotSupportedError: %v", signErr)))
				return vm.ToValue(promise)
			}
			resolve(vm.ToValue(vm.NewArrayBuffer(result)))
			return vm.ToValue(promise)
		},

		// ── verify(algorithm, key, signature, data) → Promise<boolean> ──
		"verify": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 4 {
				reject(vm.ToValue("TypeError: 4 arguments required"))
				return vm.ToValue(promise)
			}
			algName, algParams := extractAlgorithm(vm, call.Arguments[0])
			keyBytes, err := extractRawKey(vm, call.Arguments[1])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("InvalidAccessError: %v", err)))
				return vm.ToValue(promise)
			}
			sig, err := extractCryptoBytes(vm, call.Arguments[2])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("TypeError: %v", err)))
				return vm.ToValue(promise)
			}
			data, err := extractCryptoBytes(vm, call.Arguments[3])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("TypeError: %v", err)))
				return vm.ToValue(promise)
			}
			ok, verErr := doVerify(algName, algParams, keyBytes, sig, data)
			if verErr != nil {
				reject(vm.ToValue(fmt.Sprintf("NotSupportedError: %v", verErr)))
				return vm.ToValue(promise)
			}
			resolve(vm.ToValue(ok))
			return vm.ToValue(promise)
		},

		// ── generateKey(algorithm, extractable, usages) → Promise<CryptoKey> ──
		"generateKey": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 3 {
				reject(vm.ToValue("TypeError: 3 arguments required"))
				return vm.ToValue(promise)
			}
			algName, algParams := extractAlgorithm(vm, call.Arguments[0])
			extractable := call.Arguments[1].ToBoolean()
			usages := toStringSlice(call.Arguments[2].Export())

			key, genErr := doGenerateKey(vm, algName, algParams, extractable, usages)
			if genErr != nil {
				reject(vm.ToValue(fmt.Sprintf("NotSupportedError: %v", genErr)))
				return vm.ToValue(promise)
			}
			resolve(key)
			return vm.ToValue(promise)
		},

		// ── importKey(format, keyData, algorithm, extractable, usages) → Promise<CryptoKey> ──
		"importKey": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 5 {
				reject(vm.ToValue("TypeError: 5 arguments required"))
				return vm.ToValue(promise)
			}
			format := call.Arguments[0].String()
			algName, algParams := extractAlgorithm(vm, call.Arguments[2])
			extractable := call.Arguments[3].ToBoolean()
			usages := toStringSlice(call.Arguments[4].Export())

			key, impErr := doImportKey(vm, format, call.Arguments[1], algName, algParams, extractable, usages)
			if impErr != nil {
				reject(vm.ToValue(fmt.Sprintf("NotSupportedError: %v", impErr)))
				return vm.ToValue(promise)
			}
			resolve(key)
			return vm.ToValue(promise)
		},

		// ── exportKey(format, key) → Promise<ArrayBuffer> ──
		"exportKey": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 2 {
				reject(vm.ToValue("TypeError: 2 arguments required"))
				return vm.ToValue(promise)
			}
			format := call.Arguments[0].String()
			keyBytes, err := extractRawKey(vm, call.Arguments[1])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("InvalidAccessError: %v", err)))
				return vm.ToValue(promise)
			}
			// Check extractable
			obj := call.Arguments[1].ToObject(vm)
			if obj != nil {
				ext := obj.Get("extractable")
				if ext != nil && !ext.ToBoolean() {
					reject(vm.ToValue("InvalidAccessError: key is not extractable"))
					return vm.ToValue(promise)
				}
			}
			switch strings.ToLower(format) {
			case "raw":
				resolve(vm.ToValue(vm.NewArrayBuffer(keyBytes)))
			default:
				reject(vm.ToValue(fmt.Sprintf("NotSupportedError: export format '%s' not supported", format)))
			}
			return vm.ToValue(promise)
		},

		// ── deriveBits(algorithm, baseKey, length) → Promise<ArrayBuffer> ──
		"deriveBits": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 3 {
				reject(vm.ToValue("TypeError: 3 arguments required"))
				return vm.ToValue(promise)
			}
			algName, algParams := extractAlgorithm(vm, call.Arguments[0])
			keyBytes, err := extractRawKey(vm, call.Arguments[1])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("InvalidAccessError: %v", err)))
				return vm.ToValue(promise)
			}
			length := int(call.Arguments[2].ToInteger())

			result, derErr := doDeriveBits(vm, algName, algParams, keyBytes, length)
			if derErr != nil {
				reject(vm.ToValue(fmt.Sprintf("NotSupportedError: %v", derErr)))
				return vm.ToValue(promise)
			}
			resolve(vm.ToValue(vm.NewArrayBuffer(result)))
			return vm.ToValue(promise)
		},

		// ── deriveKey(algorithm, baseKey, derivedKeyAlg, extractable, usages) → Promise<CryptoKey> ──
		"deriveKey": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 5 {
				reject(vm.ToValue("TypeError: 5 arguments required"))
				return vm.ToValue(promise)
			}
			algName, algParams := extractAlgorithm(vm, call.Arguments[0])
			keyBytes, err := extractRawKey(vm, call.Arguments[1])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("InvalidAccessError: %v", err)))
				return vm.ToValue(promise)
			}
			dkAlgName, dkAlgParams := extractAlgorithm(vm, call.Arguments[2])
			extractable := call.Arguments[3].ToBoolean()
			usages := toStringSlice(call.Arguments[4].Export())

			// Determine derived key length from the derived key algorithm
			dkLen := toIntParam(dkAlgParams, "length", 256) / 8
			if dkLen <= 0 {
				dkLen = 32
			}

			bits, derErr := doDeriveBits(vm, algName, algParams, keyBytes, dkLen*8)
			if derErr != nil {
				reject(vm.ToValue(fmt.Sprintf("NotSupportedError: %v", derErr)))
				return vm.ToValue(promise)
			}

			algo := map[string]interface{}{"name": dkAlgName, "length": dkLen * 8}
			if dkAlgParams != nil {
				for k, v := range dkAlgParams {
					algo[k] = v
				}
			}
			ck := newCryptoKey(vm, "secret", extractable, algo, usages, bits)
			resolve(ck)
			return vm.ToValue(promise)
		},

		// ── wrapKey(format, key, wrappingKey, wrapAlgo) → Promise<ArrayBuffer> ──
		"wrapKey": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 4 {
				reject(vm.ToValue("TypeError: 4 arguments required"))
				return vm.ToValue(promise)
			}
			format := call.Arguments[0].String()
			if strings.ToLower(format) != "raw" {
				reject(vm.ToValue("NotSupportedError: only 'raw' format supported for wrapKey"))
				return vm.ToValue(promise)
			}
			keyBytes, err := extractRawKey(vm, call.Arguments[1])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("InvalidAccessError: %v", err)))
				return vm.ToValue(promise)
			}
			wrappingKeyBytes, err := extractRawKey(vm, call.Arguments[2])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("InvalidAccessError: %v", err)))
				return vm.ToValue(promise)
			}
			wrapAlgName, wrapAlgParams := extractAlgorithm(vm, call.Arguments[3])
			result, encErr := doEncrypt(vm, wrapAlgName, wrapAlgParams, wrappingKeyBytes, keyBytes)
			if encErr != nil {
				reject(vm.ToValue(fmt.Sprintf("OperationError: %v", encErr)))
				return vm.ToValue(promise)
			}
			resolve(vm.ToValue(vm.NewArrayBuffer(result)))
			return vm.ToValue(promise)
		},

		// ── unwrapKey(format, wrappedKey, unwrappingKey, unwrapAlgo, unwrappedKeyAlgo, extractable, keyUsages) ──
		"unwrapKey": func(call goja.FunctionCall) goja.Value {
			promise, resolve, reject := vm.NewPromise()
			if len(call.Arguments) < 7 {
				reject(vm.ToValue("TypeError: 7 arguments required"))
				return vm.ToValue(promise)
			}
			format := call.Arguments[0].String()
			if strings.ToLower(format) != "raw" {
				reject(vm.ToValue("NotSupportedError: only 'raw' format supported for unwrapKey"))
				return vm.ToValue(promise)
			}
			wrappedKey, err := extractCryptoBytes(vm, call.Arguments[1])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("TypeError: %v", err)))
				return vm.ToValue(promise)
			}
			unwrapKeyBytes, err := extractRawKey(vm, call.Arguments[2])
			if err != nil {
				reject(vm.ToValue(fmt.Sprintf("InvalidAccessError: %v", err)))
				return vm.ToValue(promise)
			}
			unwrapAlgName, unwrapAlgParams := extractAlgorithm(vm, call.Arguments[3])
			dkAlgName, dkAlgParams := extractAlgorithm(vm, call.Arguments[4])
			extractable := call.Arguments[5].ToBoolean()
			usages := toStringSlice(call.Arguments[6].Export())

			rawKey, decErr := doDecrypt(vm, unwrapAlgName, unwrapAlgParams, unwrapKeyBytes, wrappedKey)
			if decErr != nil {
				reject(vm.ToValue(fmt.Sprintf("OperationError: %v", decErr)))
				return vm.ToValue(promise)
			}

			algo := map[string]interface{}{"name": dkAlgName}
			if dkAlgParams != nil {
				for k, v := range dkAlgParams {
					algo[k] = v
				}
			}
			ck := newCryptoKey(vm, "secret", extractable, algo, usages, rawKey)
			resolve(ck)
			return vm.ToValue(promise)
		},
	}
}

// ── Core crypto operations ───────────────────────────────────────────────

func doEncrypt(vm *goja.Runtime, algName string, algParams map[string]interface{}, keyBytes, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid key size: %v", err)
	}

	switch algName {
	case "AES-GCM":
		iv, err := extractBytesFromAlgParam(vm, algParams, "iv")
		if err != nil {
			return nil, err
		}
		tagLen := toIntParam(algParams, "tagLength", 128) / 8
		aead, err := cipher.NewGCMWithTagSize(block, tagLen)
		if err != nil {
			return nil, fmt.Errorf("GCM init error: %v", err)
		}
		var additionalData []byte
		if ad, adErr := extractBytesFromAlgParam(vm, algParams, "additionalData"); adErr == nil {
			additionalData = ad
		}
		ciphertext := aead.Seal(nil, iv, plaintext, additionalData)
		return ciphertext, nil

	case "AES-CBC":
		iv, err := extractBytesFromAlgParam(vm, algParams, "iv")
		if err != nil {
			return nil, err
		}
		if len(iv) != aes.BlockSize {
			return nil, fmt.Errorf("AES-CBC iv must be %d bytes", aes.BlockSize)
		}
		padded := pkcs7Pad(plaintext, aes.BlockSize)
		ciphertext := make([]byte, len(padded))
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(ciphertext, padded)
		return ciphertext, nil

	case "AES-CTR":
		counter, err := extractBytesFromAlgParam(vm, algParams, "counter")
		if err != nil {
			return nil, err
		}
		if len(counter) != aes.BlockSize {
			return nil, fmt.Errorf("AES-CTR counter must be %d bytes", aes.BlockSize)
		}
		ciphertext := make([]byte, len(plaintext))
		stream := cipher.NewCTR(block, counter)
		stream.XORKeyStream(ciphertext, plaintext)
		return ciphertext, nil

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algName)
	}
}

func doDecrypt(vm *goja.Runtime, algName string, algParams map[string]interface{}, keyBytes, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid key size: %v", err)
	}

	switch algName {
	case "AES-GCM":
		iv, err := extractBytesFromAlgParam(vm, algParams, "iv")
		if err != nil {
			return nil, err
		}
		tagLen := toIntParam(algParams, "tagLength", 128) / 8
		aead, err := cipher.NewGCMWithTagSize(block, tagLen)
		if err != nil {
			return nil, fmt.Errorf("GCM init error: %v", err)
		}
		var additionalData []byte
		if ad, adErr := extractBytesFromAlgParam(vm, algParams, "additionalData"); adErr == nil {
			additionalData = ad
		}
		plaintext, err := aead.Open(nil, iv, ciphertext, additionalData)
		if err != nil {
			return nil, fmt.Errorf("decryption failed: %v", err)
		}
		return plaintext, nil

	case "AES-CBC":
		iv, err := extractBytesFromAlgParam(vm, algParams, "iv")
		if err != nil {
			return nil, err
		}
		if len(iv) != aes.BlockSize {
			return nil, fmt.Errorf("AES-CBC iv must be %d bytes", aes.BlockSize)
		}
		if len(ciphertext)%aes.BlockSize != 0 {
			return nil, fmt.Errorf("ciphertext length not multiple of block size")
		}
		plaintext := make([]byte, len(ciphertext))
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(plaintext, ciphertext)
		unpadded, err := pkcs7Unpad(plaintext)
		if err != nil {
			return nil, fmt.Errorf("padding error: %v", err)
		}
		return unpadded, nil

	case "AES-CTR":
		counter, err := extractBytesFromAlgParam(vm, algParams, "counter")
		if err != nil {
			return nil, err
		}
		if len(counter) != aes.BlockSize {
			return nil, fmt.Errorf("AES-CTR counter must be %d bytes", aes.BlockSize)
		}
		plaintext := make([]byte, len(ciphertext))
		stream := cipher.NewCTR(block, counter)
		stream.XORKeyStream(plaintext, ciphertext)
		return plaintext, nil

	default:
		return nil, fmt.Errorf("unsupported decryption algorithm: %s", algName)
	}
}

func doSign(algName string, algParams map[string]interface{}, keyBytes, data []byte) ([]byte, error) {
	switch algName {
	case "HMAC":
		hashName := resolveHashName(algParams)
		hashFn, _, err := getHashFunc(hashName)
		if err != nil {
			return nil, err
		}
		mac := hmac.New(hashFn, keyBytes)
		mac.Write(data)
		return mac.Sum(nil), nil
	default:
		return nil, fmt.Errorf("unsupported sign algorithm: %s", algName)
	}
}

func doVerify(algName string, algParams map[string]interface{}, keyBytes, sig, data []byte) (bool, error) {
	switch algName {
	case "HMAC":
		hashName := resolveHashName(algParams)
		hashFn, _, err := getHashFunc(hashName)
		if err != nil {
			return false, err
		}
		mac := hmac.New(hashFn, keyBytes)
		mac.Write(data)
		expected := mac.Sum(nil)
		return hmac.Equal(sig, expected), nil
	default:
		return false, fmt.Errorf("unsupported verify algorithm: %s", algName)
	}
}

func doGenerateKey(vm *goja.Runtime, algName string, algParams map[string]interface{}, extractable bool, usages []string) (interface{}, error) {
	switch algName {
	case "AES-GCM", "AES-CBC", "AES-CTR":
		length := toIntParam(algParams, "length", 256)
		keyLen := length / 8
		if keyLen != 16 && keyLen != 24 && keyLen != 32 {
			return nil, fmt.Errorf("invalid AES key length: %d", length)
		}
		keyBytes := make([]byte, keyLen)
		if _, err := rand.Read(keyBytes); err != nil {
			return nil, fmt.Errorf("random generation failed: %v", err)
		}
		algo := map[string]interface{}{"name": algName, "length": length}
		return newCryptoKey(vm, "secret", extractable, algo, usages, keyBytes), nil

	case "HMAC":
		hashName := resolveHashName(algParams)
		_, hashSize, err := getHashFunc(hashName)
		if err != nil {
			return nil, err
		}
		// Use specified length or default to hash block size
		keyLen := toIntParam(algParams, "length", hashSize*8) / 8
		if keyLen <= 0 {
			keyLen = hashSize
		}
		keyBytes := make([]byte, keyLen)
		if _, err := rand.Read(keyBytes); err != nil {
			return nil, fmt.Errorf("random generation failed: %v", err)
		}
		algo := map[string]interface{}{"name": "HMAC", "hash": map[string]interface{}{"name": hashName}, "length": keyLen * 8}
		return newCryptoKey(vm, "secret", extractable, algo, usages, keyBytes), nil

	default:
		return nil, fmt.Errorf("unsupported key generation algorithm: %s", algName)
	}
}

func doImportKey(vm *goja.Runtime, format string, keyData goja.Value, algName string, algParams map[string]interface{}, extractable bool, usages []string) (interface{}, error) {
	switch strings.ToLower(format) {
	case "raw":
		rawBytes, err := extractCryptoBytes(vm, keyData)
		if err != nil {
			return nil, fmt.Errorf("cannot read key data: %v", err)
		}
		algo := map[string]interface{}{"name": algName}
		if algParams != nil {
			for k, v := range algParams {
				algo[k] = v
			}
		}
		// For HMAC, include hash info in algorithm
		if algName == "HMAC" {
			hashName := resolveHashName(algParams)
			algo["hash"] = map[string]interface{}{"name": hashName}
			algo["length"] = len(rawBytes) * 8
		}
		// For AES-*, include length
		if strings.HasPrefix(algName, "AES-") {
			algo["length"] = len(rawBytes) * 8
		}
		return newCryptoKey(vm, "secret", extractable, algo, usages, rawBytes), nil

	default:
		return nil, fmt.Errorf("unsupported import format: %s", format)
	}
}

func doDeriveBits(vm *goja.Runtime, algName string, algParams map[string]interface{}, keyBytes []byte, lengthBits int) ([]byte, error) {
	switch algName {
	case "PBKDF2":
		salt, err := extractBytesFromAlgParam(vm, algParams, "salt")
		if err != nil {
			return nil, fmt.Errorf("PBKDF2 missing salt: %v", err)
		}
		iterations := toIntParam(algParams, "iterations", 100000)
		hashName := resolveHashName(algParams)
		hashFn, _, hashErr := getHashFunc(hashName)
		if hashErr != nil {
			return nil, hashErr
		}
		keyLen := lengthBits / 8
		if keyLen <= 0 {
			return nil, fmt.Errorf("invalid length: %d", lengthBits)
		}
		derived := pbkdf2Key(keyBytes, salt, iterations, keyLen, hashFn)
		return derived, nil

	default:
		return nil, fmt.Errorf("unsupported derivation algorithm: %s", algName)
	}
}
