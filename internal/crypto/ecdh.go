// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
)

// GenerateECDHKeyPair 生成ECDH密钥对，使用P-256曲线
func GenerateECDHKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// MarshalPublicKey 将ECDSA公钥序列化为PEM格式
func MarshalPublicKey(publicKey *ecdsa.PublicKey) ([]byte, error) {
	// 首先将公钥编码为ANS.1 DER格式
	derBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// 然后将DER编码的密钥包装在PEM块中
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// ParsePublicKey 从PEM格式解析ECDSA公钥
func ParsePublicKey(pemData []byte) (*ecdsa.PublicKey, error) {
	// 解码PEM块
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// 解析DER编码的公钥
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// 类型断言为*ecdsa.PublicKey
	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaPublicKey, nil
}

// ComputeSharedSecret 计算ECDH共享密钥
func ComputeSharedSecret(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) ([]byte, error) {
	// 计算共享密钥: x = k * Q
	x, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, privateKey.D.Bytes())
	if x == nil {
		return nil, fmt.Errorf("failed to compute shared secret")
	}

	// 将x坐标作为共享密钥，使用32字节长度
	sharedSecret := make([]byte, 32)
	xBytes := x.Bytes()
	copy(sharedSecret[32-len(xBytes):], xBytes)

	return sharedSecret, nil
}

// 以下是为了测试目的的辅助函数，模拟JavaScript的Web Crypto API行为

// GenerateTestKeyPair 生成测试用的密钥对，并返回与前端兼容的格式
func GenerateTestKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := GenerateECDHKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// ExportPublicKeyForJS 将公钥导出为JavaScript兼容的Base64格式
func ExportPublicKeyForJS(publicKey *ecdsa.PublicKey) (string, error) {
	// 使用未压缩格式，与JavaScript保持一致
	// 格式: 0x04 + X(32字节) + Y(32字节)
	// 总长度: 1 + 32 + 32 = 65字节
	x := publicKey.X.Bytes()
	y := publicKey.Y.Bytes()

	// 确保X和Y都是32字节
	xBytes := make([]byte, 32)
	yBytes := make([]byte, 32)
	copy(xBytes[32-len(x):], x)
	copy(yBytes[32-len(y):], y)

	// 构建未压缩格式: 0x04 || X || Y
	result := make([]byte, 65)
	result[0] = 0x04
	copy(result[1:33], xBytes)
	copy(result[33:65], yBytes)

	// 转换为Base64
	return EncodeBase64(result), nil
}

// ImportPublicKeyFromJS 从JavaScript的Base64格式导入公钥
func ImportPublicKeyFromJS(base64Key string) (*ecdsa.PublicKey, error) {
	// 解码Base64
	data, err := DecodeBase64(base64Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 key: %w", err)
	}

	// 验证数据长度
	if len(data) != 65 {
		return nil, fmt.Errorf("invalid key length, expected 65 bytes, got %d", len(data))
	}

	// 验证格式标记(0x04表示未压缩格式)
	if data[0] != 0x04 {
		return nil, fmt.Errorf("invalid key format, expected uncompressed format (0x04)")
	}

	// 提取X和Y坐标
	x := new(big.Int).SetBytes(data[1:33])
	y := new(big.Int).SetBytes(data[33:65])

	// 创建公钥
	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return publicKey, nil
}