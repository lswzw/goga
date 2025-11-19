package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptAES256GCM_Success(t *testing.T) {
	// 使用一个可预测的密钥进行测试
	key := make([]byte, AES256KeySize)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("这是一个非常机密的消息")

	// 加密明文
	encrypted, err := EncryptAES256GCM(key, plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 解密密文
	decrypted, err := DecryptAES256GCM(key, encrypted)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	// 检查解密后的文本是否与原始明文匹配
	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("解密后的文本与原始明文不匹配。\ngot: %s\nwant: %s", decrypted, plaintext)
	}
}

func TestDecryptAES256GCM_InvalidKeySize(t *testing.T) {
	key := []byte("shortkey")
	ciphertext := []byte("some ciphertext")

	_, err := DecryptAES256GCM(key, ciphertext)
	if err == nil {
		t.Error("期望因密钥大小无效而返回错误，但未收到错误")
	}
}

func TestDecryptAES256GCM_CiphertextTooShort(t *testing.T) {
	key := make([]byte, AES256KeySize)
	ciphertext := []byte("short") // 比任何可能的 nonce 都短

	_, err := DecryptAES256GCM(key, ciphertext)
	if err == nil {
		t.Error("期望因密文太短而返回错误，但未收到错误")
	}
}

func TestDecryptAES256GCM_WrongKey(t *testing.T) {
	key1 := make([]byte, AES256KeySize)
	key2 := make([]byte, AES256KeySize)
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1) // 不同的密钥
	}

	plaintext := []byte("另一个秘密")

	encrypted, err := EncryptAES256GCM(key1, plaintext)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 尝试使用错误的密钥解密
	_, err = DecryptAES256GCM(key2, encrypted)
	if err == nil {
		t.Error("期望使用错误的密钥解密时返回错误，但未收到错误")
	}
}
