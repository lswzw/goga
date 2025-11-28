// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// DerivedKeys 包含从共享密钥派生的各种密钥
type DerivedKeys struct {
	RequestKey  []byte // 用于加密请求的密钥
	ResponseKey []byte // 用于解密响应的密钥
	MACKey      []byte // 用于消息认证的密钥
	Salt        []byte // 派生密钥时使用的盐值
}

// DeriveKeys 使用HKDF从共享密钥派生多个独立的密钥
// 实现基于RFC 5869标准
func DeriveKeys(sharedSecret []byte, info string) (*DerivedKeys, error) {
	// 生成一个16字节的随机盐值
	salt := make([]byte, 16)
	if _, err := RandomBytes(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// 调用完整的HKDF派生函数
	return DeriveKeysWithSalt(sharedSecret, salt, info)
}

// DeriveKeysWithSalt 使用指定的盐值从共享密钥派生密钥
func DeriveKeysWithSalt(sharedSecret, salt []byte, info string) (*DerivedKeys, error) {
	// 使用HKDF-Extract从共享密钥和盐值提取PRK
	prk := hkdfExtract(salt, sharedSecret)

	// 使用HKDF-Expand从PRK派生密钥材料
	// 我们需要3个32字节的密钥(requestKey, responseKey, macKey)
	keyMaterial := hkdfExpand(prk, []byte(info), 96) // 32 * 3 = 96

	// 将密钥材料分成三个32字节的密钥
	requestKey := keyMaterial[0:32]
	responseKey := keyMaterial[32:64]
	macKey := keyMaterial[64:96]

	return &DerivedKeys{
		RequestKey:  requestKey,
		ResponseKey: responseKey,
		MACKey:      macKey,
		Salt:        salt,
	}, nil
}

// hkdfExtract 实现HKDF-Extract函数
// PRK = HMAC-SHA256(salt, IKM)
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		// 如果盐值为空，使用零填充的哈希长度
		salt = make([]byte, sha256.Size)
	}

	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand 实现HKDF-Expand函数
// OKM = HKDF-Expand(PRK, info, L)
func hkdfExpand(prk, info []byte, length int) []byte {
	// RFC 5869:
	// N = ceil(L / HashLen)
	// T = T(1) | T(2) | T(3) | ... | T(N)
	// OKM = first L octets of T
	// 其中:
	// T(0) = empty string (zero length)
	// T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
	// T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
	// T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
	// ...

	hashLen := sha256.Size
	n := (length + hashLen - 1) / hashLen // ceil(length / hashLen)

	var okm []byte
	var t []byte

	for i := 1; i <= n; i++ {
		// 构建HMAC输入: T(i-1) | info | i
		mac := hmac.New(sha256.New, prk)
		mac.Write(t) // T(i-1)，对于i=1是空字符串
		mac.Write(info)
		mac.Write([]byte{byte(i)})

		t = mac.Sum(nil)
		okm = append(okm, t...)
	}

	return okm[:length]
}

// RandomBytes 生成指定长度的随机字节
func RandomBytes(b []byte) (int, error) {
	return rand.Read(b)
}

// ToLittleEndian 将uint32转换为小端字节切片
func ToLittleEndian(value uint32) []byte {
	result := make([]byte, 4)
	binary.LittleEndian.PutUint32(result, value)
	return result
}

// ToBigEndian 将uint32转换为大端字节切片
func ToBigEndian(value uint32) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, value)
	return result
}