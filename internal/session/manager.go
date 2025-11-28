// Copyright (c) 2025 wangke <464829928@qq.com>
//
// This software is released under the AGPL-3.0 license.
// For more details, see the LICENSE file in the root directory.

package session

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"goga/internal/crypto"
)

// Session 表示一个ECDH会话
type Session struct {
	SessionID   string    // 会话唯一标识符
	RequestKey  []byte    // 用于加密请求的密钥
	ResponseKey []byte    // 用于解密响应的密钥
	MACKey      []byte    // 用于消息认证的密钥
	CreatedAt   time.Time  // 会话创建时间
	ExpiresAt   time.Time  // 会话过期时间
}

// Manager 管理ECDH会话
type Manager struct {
	sessions    map[string]*Session // 会话存储
	mutex       sync.RWMutex      // 读写锁
	sessionTTL  time.Duration    // 会话生存时间
	cleanupTick *time.Ticker     // 定期清理的ticker
	stopCleanup chan struct{}    // 停止清理的信号
}

// NewManager 创建一个新的会话管理器
func NewManager(sessionTTL time.Duration) *Manager {
	m := &Manager{
		sessions:    make(map[string]*Session),
		sessionTTL:  sessionTTL,
		stopCleanup: make(chan struct{}),
	}

	// 启动定期清理goroutine
	m.startCleanup()

	return m
}

// Stop 停止会话管理器，释放资源
func (m *Manager) Stop() {
	if m.cleanupTick != nil {
		close(m.stopCleanup)
		m.cleanupTick.Stop()
	}
}

// CreateSession 创建一个新的ECDH会话
func (m *Manager) CreateSession(clientPublicKey string) (*Session, string, error) {
	// 1. 生成服务器ECDH密钥对
	serverPrivateKey, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate server key pair: %w", err)
	}

	// 2. 导入客户端公钥
	clientPubKey, err := crypto.ImportPublicKeyFromJS(clientPublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to import client public key: %w", err)
	}

	// 3. 计算共享密钥
	sharedSecret, err := crypto.ComputeSharedSecret(serverPrivateKey, clientPubKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	// 4. 派生密钥
	derivedKeys, err := crypto.DeriveKeys(sharedSecret, "GoGa encryption session")
	if err != nil {
		return nil, "", fmt.Errorf("failed to derive keys: %w", err)
	}

	// 5. 生成会话ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate session ID: %w", err)
	}

	// 6. 创建会话对象
	now := time.Now()
	session := &Session{
		SessionID:   sessionID,
		RequestKey:  derivedKeys.RequestKey,
		ResponseKey: derivedKeys.ResponseKey,
		MACKey:      derivedKeys.MACKey,
		CreatedAt:   now,
		ExpiresAt:   now.Add(m.sessionTTL),
	}

	// 7. 存储会话
	m.mutex.Lock()
	m.sessions[sessionID] = session
	m.mutex.Unlock()

	slog.Debug("Created new ECDH session", "sessionID", sessionID, "expiresAt", session.ExpiresAt)

	// 8. 导出服务器公钥
	serverPublicKey, err := crypto.ExportPublicKeyForJS(&serverPrivateKey.PublicKey)
	if err != nil {
		m.mutex.Lock()
		delete(m.sessions, sessionID)
		m.mutex.Unlock()
		return nil, "", fmt.Errorf("failed to export server public key: %w", err)
	}

	return session, serverPublicKey, nil
}

// GetSession 获取指定ID的会话
func (m *Manager) GetSession(sessionID string) (*Session, bool) {
	m.mutex.RLock()
	session, exists := m.sessions[sessionID]
	m.mutex.RUnlock()

	// 检查会话是否过期
	if exists && time.Now().After(session.ExpiresAt) {
		m.mutex.Lock()
		delete(m.sessions, sessionID)
		m.mutex.Unlock()
		return nil, false
	}

	return session, exists
}

// DeleteSession 删除指定ID的会话
func (m *Manager) DeleteSession(sessionID string) {
	m.mutex.Lock()
	delete(m.sessions, sessionID)
	m.mutex.Unlock()
}

// startCleanup 启动定期清理过期会话的goroutine
func (m *Manager) startCleanup() {
	// 每5分钟清理一次过期会话
	m.cleanupTick = time.NewTicker(5 * time.Minute)

	go func() {
		for {
			select {
			case <-m.cleanupTick.C:
				m.cleanupExpiredSessions()
			case <-m.stopCleanup:
				return
			}
		}
	}()
}

// cleanupExpiredSessions 清理所有过期的会话
func (m *Manager) cleanupExpiredSessions() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	now := time.Now()
	var expiredCount int

	for sessionID, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, sessionID)
			expiredCount++
		}
	}

	if expiredCount > 0 {
		slog.Debug("Cleaned up expired sessions", "count", expiredCount)
	}
}

// generateSessionID 生成一个随机的会话ID
func generateSessionID() (string, error) {
	// 生成一个16字节的随机值
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	// 转换为Base64字符串
	return base64.URLEncoding.EncodeToString(b), nil
}

// GetServerPublicKey 在CreateSession中生成的服务器公钥
// 注意：这是一个临时解决方案，实际实现可能需要重新设计接口
func (m *Manager) GetServerPublicKey(sessionID string) (string, error) {
	// 这是一个占位符实现
	// 在实际实现中，应该从会话中获取服务器公钥
	// 或者修改CreateSession的返回值
	return "", fmt.Errorf("not implemented")
}