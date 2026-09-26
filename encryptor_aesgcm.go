package secretrotation

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// AESGCMEncryptor 是 Encryptor 的生产可用参考实现：每个密文由随机
// 12 字节 nonce 与 AES-GCM 密封结果拼接而成，GCM 的认证标签保证密文
// 未被篡改。nonce 随机化使得相同明文产生不同密文；解密失败只返回
// 通用错误，错误文本不含密钥名之外的输入内容，更不含明文。
//
// 主密钥（KEK）以 32 字节（AES-256）形式注入；真实部署应来自 KMS/HSM，
// 而非硬编码。所有版本共用同一 KEK，版本不可变性由服务层保证。
type AESGCMEncryptor struct {
	aead cipher.AEAD
}

// NewAESGCMEncryptor 使用给定主密钥构造 AES-GCM 加密器，
// key 长度必须为 16、24 或 32 字节。
func NewAESGCMEncryptor(key []byte) (*AESGCMEncryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretrotation: invalid KEK: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretrotation: init GCM failed: %w", err)
	}
	return &AESGCMEncryptor{aead: aead}, nil
}

// Encrypt 密封单个版本明文。keyName/version 作为附加数据绑定进密文，
// 防止把某密钥某版本的密文挪用到别处（密文搬运攻击）。
func (e *AESGCMEncryptor) Encrypt(_ context.Context, keyName string, version int, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secretrotation: generate nonce: %w", err)
	}
	aad := buildAAD(keyName, version)
	sealed := e.aead.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(nonce)+len(sealed))
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// Decrypt 打开密文并校验 AAD；任何失败都折叠为通用解密错误。
func (e *AESGCMEncryptor) Decrypt(_ context.Context, keyName string, version int, blob []byte) ([]byte, error) {
	ns := e.aead.NonceSize()
	if len(blob) < ns+1 {
		return nil, errors.New("secretrotation: ciphertext too short")
	}
	nonce, sealed := blob[:ns], blob[ns:]
	plaintext, err := e.aead.Open(nil, nonce, sealed, buildAAD(keyName, version))
	if err != nil {
		return nil, errors.New("secretrotation: decrypt failed")
	}
	return plaintext, nil
}

// buildAAD 生成绑定“密钥名 + 版本号”的附加认证数据。格式：
//
//	SR1 || len(name) uint16 BE || name || version uint64 BE
func buildAAD(keyName string, version int) []byte {
	aad := make([]byte, 0, 4+2+len(keyName)+8)
	aad = append(aad, 'S', 'R', '0', '1')
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(keyName)))
	aad = append(aad, l[:]...)
	aad = append(aad, keyName...)
	var v [8]byte
	binary.BigEndian.PutUint64(v[:], uint64(version))
	aad = append(aad, v[:]...)
	return aad
}
