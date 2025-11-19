package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

const (
	// AES256KeySize 是 AES-256 所需的密钥大小（32 字节）。
	AES256KeySize = 32
)

// EncryptAES256GCM 使用 AES-256-GCM 加密明文。
// 输出的字节切片包含 nonce，前缀在密文之前。
func EncryptAES256GCM(key, plaintext []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("无效的密钥大小：必须是 %d 字节", AES256KeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal 会将密文附加到 nonce 之后，并返回合并后的切片。
	// 我们将 nonce 作为第一个参数传递，以将其前缀到输出中。
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAES256GCM 使用 AES-256-GCM 解密密文。
// 它期望输入的字节切片中，nonce 前缀在密文之前。
func DecryptAES256GCM(key, ciphertextWithNonce []byte) ([]byte, error) {
	if len(key) != AES256KeySize {
		return nil, fmt.Errorf("无效的密钥大小：必须是 %d 字节", AES256KeySize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextWithNonce) < nonceSize {
		return nil, fmt.Errorf("密文太短")
	}

	nonce, ciphertext := ciphertextWithNonce[:nonceSize], ciphertextWithNonce[nonceSize:]

	// Open 会解密密文并验证认证标签。
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("解密失败: %w", err)
	}

	return plaintext, nil
}
