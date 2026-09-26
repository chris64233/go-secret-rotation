package secretrotation

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// encryptor 使用 AES-256-GCM 对密钥明文做信封加密，
// 保证持久化层只出现密文。
type encryptor struct {
	aead cipher.AEAD
}

// newEncryptor 要求 32 字节的主密钥。
func newEncryptor(masterKey []byte) (*encryptor, error) {
	if len(masterKey) != 32 {
		return nil, newError(KindInvalidInput, "newEncryptor", "master key must be 32 bytes")
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("newEncryptor: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("newEncryptor: %w", err)
	}
	return &encryptor{aead: aead}, nil
}

// encrypt 返回 nonce||ciphertext。
func (e *encryptor) encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}
	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *encryptor) decrypt(ciphertext []byte) ([]byte, error) {
	ns := e.aead.NonceSize()
	if len(ciphertext) < ns {
		return nil, newError(KindInvalidState, "decrypt", "ciphertext too short")
	}
	plain, err := e.aead.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
	if err != nil {
		return nil, newError(KindInvalidState, "decrypt", "ciphertext cannot be decrypted")
	}
	return plain, nil
}

// newID 生成带前缀的随机 ID。
func newID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}
