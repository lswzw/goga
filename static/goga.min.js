/**
 * Copyright (c) 2025 wangke <464829928@qq.com>
 *
 * This software is released under the AGPL-3.0 license.
 * For more details, see the LICENSE file in the root directory.
 */
// GoGa Client-Side Encryption Script (Fetch & XHR Interceptor)
(function() {
    'use strict';

    // 全局配置，允许用户从外部定义要排除的URL
    // 示例: window.gogaCryptoConfig = { excludeUrls: ['/api/login', /^\/auth\//] };
    const gogaCryptoConfig = {
        excludeUrls: (window.gogaCryptoConfig && window.gogaCryptoConfig.excludeUrls) || [],
    };

    /**
     * 检查给定的URL是否应该被排除在加密之外。
     * @param {string} url 要检查的URL。
     * @returns {boolean} 如果URL应该被排除，则返回true。
     */
    function isUrlExcluded(url) {
        for (const pattern of gogaCryptoConfig.excludeUrls) {
            if (typeof pattern === 'string' && url.includes(pattern)) {
                return true;
            }
            if (pattern instanceof RegExp && pattern.test(url)) {
                return true;
            }
        }
        return false;
    }

    // First, check for a secure context.
    if (!window.crypto || !window.crypto.subtle) {
        console.error(
            'GoGa 加密中止: 此脚本需要安全上下文 (HTTPS 或 localhost)。 ' +
            'window.crypto.subtle API 不可用，加密已禁用。 ' +
            '请通过 HTTPS 或 localhost 提供您的应用程序。'
        );
        return; // Stop execution if crypto is not available.
    }


    // 会话缓存，用于存储ECDH会话相关数据
    let sessionCache = {
        sessionId: null,
        clientKeyPair: null,
        requestKey: null,    // 用于加密请求的AES密钥
        responseKey: null,   // 用于解密响应的AES密钥
        expires: 0,         // 过期时间戳 (ms)
    };

    // 保存原始的 fetch 和 XHR 函数
    const originalFetch = window.fetch;
    const originalXhrOpen = XMLHttpRequest.prototype.open;
    const originalXhrSend = XMLHttpRequest.prototype.send;
    const originalXhrSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;

    /**
     * 将 ArrayBuffer 转换为 Base64 字符串。
     * @param {ArrayBuffer} buffer The buffer to convert.
     * @returns {string} The Base64 encoded string.
     */
    function arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    }

    /**
     * 将 Base64 字符串转换为 ArrayBuffer。
     * @param {string} base64 The Base64 encoded string.
     * @returns {ArrayBuffer} The decoded ArrayBuffer.
     */
    function base64ToArrayBuffer(base64) {
        const binaryString = window.atob(base64);
        const len = binaryString.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // ECDH密钥交换相关函数

    /**
     * 生成ECDH密钥对。
     * @returns {Promise<CryptoKeyPair>} ECDH密钥对
     */
    async function generateECDHKeyPair() {
        try {
            const keyPair = await window.crypto.subtle.generateKey(
                {
                    name: "ECDH",
                    namedCurve: "P-256",
                },
                true, // 可提取，用于导出公钥
                ["deriveKey", "deriveBits"]
            );
            return keyPair;
        } catch (error) {
            console.error('GoGa: ECDH密钥对生成失败:', error);
            throw new Error(`ECDH密钥对生成失败: ${error.message}`);
        }
    }

    /**
     * 导出ECDH公钥为Base64编码的格式。
     * @param {CryptoKey} publicKey 要导出的公钥
     * @returns {Promise<string>} Base64编码的公钥
     */
    async function exportPublicKey(publicKey) {
        try {
            const exported = await window.crypto.subtle.exportKey(
                "spki",
                publicKey
            );
            return arrayBufferToBase64(exported);
        } catch (error) {
            console.error('GoGa: 公钥导出失败:', error);
            throw new Error(`公钥导出失败: ${error.message}`);
        }
    }

    /**
     * 从Base64编码的字符串导入ECDH公钥。
     * @param {string} base64PublicKey Base64编码的公钥
     * @returns {Promise<CryptoKey>} 导入的公钥
     */
    async function importPublicKey(base64PublicKey) {
        try {
            const publicKeyBuffer = base64ToArrayBuffer(base64PublicKey);
            return await window.crypto.subtle.importKey(
                "spki",
                publicKeyBuffer,
                {
                    name: "ECDH",
                    namedCurve: "P-256",
                },
                false, // 不可提取
                []
            );
        } catch (error) {
            console.error('GoGa: 公钥导入失败:', error);
            throw new Error(`公钥导入失败: ${error.message}`);
        }
    }

    /**
     * 使用ECDH计算共享密钥。
     * @param {CryptoKey} privateKey 本地私钥
     * @param {CryptoKey} publicKey 远程公钥
     * @returns {Promise<ArrayBuffer>} 共享密钥
     */
    async function computeSharedSecret(privateKey, publicKey) {
        try {
            return await window.crypto.subtle.deriveBits(
                {
                    name: "ECDH",
                    public: publicKey,
                },
                privateKey,
                256 // 派生256位(32字节)的共享密钥
            );
        } catch (error) {
            console.error('GoGa: 共享密钥计算失败:', error);
            throw new Error(`共享密钥计算失败: ${error.message}`);
        }
    }

    /**
     * 使用HKDF从共享密钥派生多个独立的密钥。
     * @param {ArrayBuffer} sharedSecret ECDH共享密钥
     * @param {ArrayBuffer} salt 盐值(可选)
     * @returns {Promise<Object>} 包含各种派生密钥的对象
     */
    async function deriveKeys(sharedSecret, salt = null) {
        try {
            // 如果没有提供盐值，生成一个随机的
            const hkdfSalt = salt || window.crypto.getRandomValues(new Uint8Array(16));
            
            // 导入共享密钥作为HKDF的输入
            const hkdfKey = await window.crypto.subtle.importKey(
                "raw",
                sharedSecret,
                "HKDF",
                false,
                ["deriveKey"]
            );

            // 派生请求加密密钥
            const requestKey = await window.crypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: hkdfSalt,
                    info: new TextEncoder().encode("GoGa request encryption"),
                },
                hkdfKey,
                { name: "AES-GCM", length: 256 },
                false,
                ["encrypt"]
            );

            // 派生响应解密密钥
            const responseKey = await window.crypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: hkdfSalt,
                    info: new TextEncoder().encode("GoGa response decryption"),
                },
                hkdfKey,
                { name: "AES-GCM", length: 256 },
                false,
                ["decrypt"]
            );

            // 派生消息认证密钥
            const macKey = await window.crypto.subtle.deriveKey(
                {
                    name: "HKDF",
                    hash: "SHA-256",
                    salt: hkdfSalt,
                    info: new TextEncoder().encode("GoGa message authentication"),
                },
                hkdfKey,
                { name: "HMAC", hash: "SHA-256" },
                false,
                ["verify"]
            );

            return {
                requestKey,
                responseKey,
                macKey,
                salt: hkdfSalt
            };
        } catch (error) {
            console.error('GoGa: 密钥派生失败:', error);
            throw new Error(`密钥派生失败: ${error.message}`);
        }
    }

    /**
     * 使用 AES-GCM 加密数据。
     * @param {string|CryptoKey} key - Base64编码的加密密钥或CryptoKey对象。
     * @param {ArrayBuffer} dataToEncrypt - 要加密的 ArrayBuffer 数据。
     * @returns {Promise<string>} - 返回一个 Promise，解析为 Base64 编码的加密数据 (iv + ciphertext)。
     */
    async function encryptData(key, dataToEncrypt) {
        let cryptoKey;
        
        if (typeof key === 'string') {
            // 兼容旧的Base64密钥格式
            const keyBuffer = base64ToArrayBuffer(key);
            cryptoKey = await window.crypto.subtle.importKey(
                'raw',
                keyBuffer,
                { name: 'AES-GCM' },
                false,
                ['encrypt']
            );
        } else {
            // 新的ECDH派生密钥
            cryptoKey = key;
        }
        
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            dataToEncrypt
        );
        const combinedBuffer = new Uint8Array(iv.length + ciphertextBuffer.byteLength);
        combinedBuffer.set(iv, 0);
        combinedBuffer.set(new Uint8Array(ciphertextBuffer), iv.length);
        return arrayBufferToBase64(combinedBuffer.buffer);
    }

    /**
     * 使用 AES-GCM 解密数据。
     * @param {string|CryptoKey} key - Base64编码的加密密钥或CryptoKey对象。
     * @param {string} base64Encrypted - Base64 编码的加密数据 (iv + ciphertext)。
     * @returns {Promise<ArrayBuffer>} - 返回一个 Promise，解析为解密后的 ArrayBuffer。
     */
    async function decryptData(key, base64Encrypted) {
        let cryptoKey;
        
        if (typeof key === 'string') {
            // 兼容旧的Base64密钥格式
            const keyBuffer = base64ToArrayBuffer(key);
            cryptoKey = await window.crypto.subtle.importKey(
                'raw',
                keyBuffer,
                { name: 'AES-GCM' },
                false,
                ['decrypt']
            );
        } else {
            // 新的ECDH派生密钥
            cryptoKey = key;
        }
        
        const encryptedData = base64ToArrayBuffer(base64Encrypted);
        const iv = encryptedData.slice(0, 12);
        const ciphertext = encryptedData.slice(12);
        
        return await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            cryptoKey,
            ciphertext
        );
    }



    /**
     * 初始化ECDH会话，执行密钥交换并派生加密密钥。
     * @returns {Promise<Object>} 包含会话信息的对象
     */
    async function initializeECDHSession() {
        try {
            console.log('GoGa: 开始初始化ECDH会话...');
            
            // 检查是否有有效的会话缓存
            const now = Date.now();
            if (sessionCache.sessionId && sessionCache.requestKey && 
                sessionCache.responseKey && now < sessionCache.expires) {
                console.log('GoGa: 使用缓存的ECDH会话。');
                return {
                    sessionId: sessionCache.sessionId,
                    requestKey: sessionCache.requestKey,
                    responseKey: sessionCache.responseKey
                };
            }

            // 1. 生成客户端ECDH密钥对
            console.log('GoGa: 生成ECDH密钥对...');
            const clientKeyPair = await generateECDHKeyPair();
            
            // 2. 导出客户端公钥
            console.log('GoGa: 导出客户端公钥...');
            const clientPublicKeyBase64 = await exportPublicKey(clientKeyPair.publicKey);
            
            // 3. 向服务器发送客户端公钥，获取服务器公钥
            console.log('GoGa: 向服务器发送公钥交换请求...');
            const keyExchangeResponse = await originalFetch('/goga/api/v1/key-exchange', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    clientPublicKey: clientPublicKeyBase64
                })
            });
            
            if (!keyExchangeResponse.ok) {
                throw new Error('密钥交换请求失败');
            }
            
            const { serverPublicKey: serverPublicKeyBase64, sessionId, ttl } = await keyExchangeResponse.json();
            
            // 4. 导入服务器公钥
            console.log('GoGa: 导入服务器公钥...');
            const serverPublicKey = await importPublicKey(serverPublicKeyBase64);
            
            // 5. 计算共享密钥
            console.log('GoGa: 计算共享密钥...');
            const sharedSecret = await computeSharedSecret(clientKeyPair.privateKey, serverPublicKey);
            
            // 6. 派生加密/解密密钥
            console.log('GoGa: 派生加密密钥...');
            const { requestKey, responseKey } = await deriveKeys(sharedSecret);
            
            // 7. 缓存会话信息
            const sessionTtlMs = (ttl * 1000 * 0.8) || (15 * 60 * 1000); // 默认15分钟
            
            sessionCache = {
                sessionId: sessionId,
                clientKeyPair: clientKeyPair,
                requestKey: requestKey,
                responseKey: responseKey,
                expires: Date.now() + sessionTtlMs
            };
            
            console.log('GoGa: ECDH会话初始化成功。');
            return {
                sessionId: sessionId,
                requestKey: requestKey,
                responseKey: responseKey
            };
        } catch (error) {
            console.error('GoGa: ECDH会话初始化失败:', error);
            sessionCache = {
                sessionId: null,
                clientKeyPair: null,
                requestKey: null,
                responseKey: null,
                expires: 0
            };
            throw error;
        }
    }

    /**
     * 检查ECDH会话是否有效，无效则重新初始化。
     * @returns {Promise<Object>} 包含会话信息的对象
     */
    async function ensureECDHSession() {
        const now = Date.now();
        if (sessionCache.sessionId && sessionCache.requestKey && 
            sessionCache.responseKey && now < sessionCache.expires) {
            return {
                sessionId: sessionCache.sessionId,
                requestKey: sessionCache.requestKey,
                responseKey: sessionCache.responseKey
            };
        }
        
        return await initializeECDHSession();
    }
    
    /**
     * 构建使用ECDH密钥的加密载荷。
     * @param {string} bodyStr 原始请求体字符串。
     * @param {string} originalContentType 原始Content-Type头。
     * @returns {Promise<object>} 用于网关的最终载荷。
     */
    async function buildECDHEncryptedPayload(bodyStr, originalContentType) {
        const encoder = new TextEncoder();
        const contentTypeBytes = encoder.encode(originalContentType);
        const bodyBytes = encoder.encode(bodyStr);

        if (contentTypeBytes.length > 255) {
            throw new Error('Content-Type header is too long (max 255 bytes).');
        }

        const payloadBuffer = new Uint8Array(1 + contentTypeBytes.length + bodyBytes.length);
        payloadBuffer[0] = contentTypeBytes.length;
        payloadBuffer.set(contentTypeBytes, 1);
        payloadBuffer.set(bodyBytes, 1 + contentTypeBytes.length);

        // 确保有有效的ECDH会话
        const { sessionId, requestKey } = await ensureECDHSession();
        
        // 生成随机IV (12字节)
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        
        // 使用派生的请求密钥加密数据
        const ciphertextBuffer = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            requestKey,
            payloadBuffer.buffer
        );
        
        // 将IV与密文合并
        const combinedBuffer = new Uint8Array(iv.length + ciphertextBuffer.byteLength);
        combinedBuffer.set(iv, 0);
        combinedBuffer.set(new Uint8Array(ciphertextBuffer), iv.length);
        
        // 使用ECDH派生的密钥加密IV
        const encryptedIV = await window.crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: window.crypto.getRandomValues(new Uint8Array(12)) }, // 用于加密IV的IV
            requestKey,
            iv
        );
        
        return {
            version: "1.0",
            sessionId: sessionId,
            encryptedData: arrayBufferToBase64(ciphertextBuffer), // 只返回密文，不包含IV
            encryptedIV: arrayBufferToBase64(encryptedIV), // 加密的IV
            ivLength: iv.length // IV长度，用于解密
        };
    }



    /**
     * 解密使用ECDH密钥加密的响应数据。
     * @param {Object} encryptedResponse 加密的响应对象。
     * @returns {Promise<string>} 解密后的响应字符串。
     */
    async function decryptECDHResponse(encryptedResponse) {
        try {
            // 确保有有效的ECDH会话
            const { sessionId, responseKey } = await ensureECDHSession();
            
            // 验证会话ID匹配
            if (encryptedResponse.sessionId !== sessionId) {
                throw new Error('会话ID不匹配');
            }
            
            // 解码Base64加密数据
            const encryptedData = base64ToArrayBuffer(encryptedResponse.encryptedData);
            const encryptedIV = base64ToArrayBuffer(encryptedResponse.encryptedIV);
            const ivLength = encryptedResponse.ivLength || 12;
            
            // 使用响应密钥解密IV
            const iv = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: window.crypto.getRandomValues(new Uint8Array(12)) },
                responseKey,
                encryptedIV
            );
            
            // 确保解密的IV长度正确
            if (iv.byteLength !== ivLength) {
                throw new Error('解密后的IV长度不匹配');
            }
            
            // 使用解密的IV解密数据
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                responseKey,
                encryptedData
            );
            
            // 解析解密后的数据
            const decryptedArray = new Uint8Array(decryptedBuffer);
            const contentTypeLength = decryptedArray[0];
            // const contentTypeBytes = decryptedArray.slice(1, 1 + contentTypeLength); // 保留以备将来使用
            const bodyBytes = decryptedArray.slice(1 + contentTypeLength);
            
            // const contentType = new TextDecoder().decode(contentTypeBytes); // 保留以备将来使用
            const body = new TextDecoder().decode(bodyBytes);
            
            return body;
        } catch (error) {
            console.error('GoGa: ECDH响应解密失败:', error);
            throw new Error(`ECDH响应解密失败: ${error.message}`);
        }
    }

    // Intercept fetch
    window.fetch = async function(...args) {
        const [url, options] = args;

        const isApiPost = options && options.method && options.method.toUpperCase() === 'POST' &&
                          options.body && typeof options.body === 'string' &&
                          !url.toString().includes('/goga/api/v1/key-exchange');

        if (isApiPost) {
            // 检查URL是否在排除列表中
            if (isUrlExcluded(url.toString())) {
                console.log(`GoGa: URL "${url}" 在排除列表中，跳过加密。`);
                return originalFetch(...args);
            }

            try {
                const originalContentType = (options.headers && (options.headers['Content-Type'] || options.headers['content-type'])) || 'application/json';
                console.log(`GoGa: 拦截到对 "${url}" 的 fetch POST 请求。尝试ECDH加密。`);
                
                // 使用ECDH加密替代原有的对称加密
                const gogaPayload = await buildECDHEncryptedPayload(options.body, originalContentType);
                console.log('GoGa: fetch 请求体已使用ECDH加密。');

                const newOptions = { ...options };
                newOptions.body = JSON.stringify(gogaPayload);
                newOptions.headers = { ...newOptions.headers, 'Content-Type': 'application/json;charset=UTF-8' };

                console.log(`GoGa: 正在发送ECDH加密的 fetch 请求体到 "${url}"。`);
                
                // 发送请求并处理响应
                const response = await originalFetch(url, newOptions);
                
                // 检查响应是否为ECDH加密格式
                if (response.ok && response.headers.get('Content-Type') && 
                    response.headers.get('Content-Type').includes('application/json')) {
                    try {
                        const clonedResponse = response.clone();
                        const responseData = await clonedResponse.json();
                        
                        // 如果响应包含ECDH加密标识，尝试解密
                        if (responseData.version === "1.0" && responseData.sessionId && 
                            responseData.encryptedData && responseData.encryptedIV) {
                            const decryptedBody = await decryptECDHResponse(responseData);
                            
                            // 返回新的解密响应
                            return new Response(decryptedBody, {
                                status: response.status,
                                statusText: response.statusText,
                                headers: response.headers
                            });
                        }
                    } catch (decryptError) {
                        console.warn(`GoGa: 响应解密失败，返回原始响应:`, decryptError.message);
                    }
                }
                
                return response;

            } catch (e) {
                console.warn(`GoGa: 对 "${url}" 的 fetch 请求未加密。原因:`, e.message);
                return originalFetch(...args);
            }
        }

        return originalFetch(...args);
    };
    
    // Intercept XMLHttpRequest
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this._goga_method = method;
        this._goga_url = url;
        this._goga_headers = {}; // Reset headers
        return originalXhrOpen.apply(this, [method, url, ...rest]);
    };

    XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
        this._goga_headers[header.toLowerCase()] = value;
        return originalXhrSetRequestHeader.apply(this, arguments);
    };

    XMLHttpRequest.prototype.send = function(body) {
        const self = this;
        const url = self._goga_url;

        const isApiPost = self._goga_method && self._goga_method.toUpperCase() === 'POST' &&
            body && typeof body === 'string' &&
            !url.toString().includes('/goga/api/v1/key-exchange');

        if (!isApiPost) {
            return originalXhrSend.apply(self, arguments);
        }

        // 检查URL是否在排除列表中
        if (isUrlExcluded(url.toString())) {
            console.log(`GoGa: URL "${url}" 在排除列表中，跳过加密。`);
            originalXhrSend.apply(self, arguments);
            return;
        }

        (async function() {
            try {
                const originalContentType = self._goga_headers['content-type'] || 'application/json';
                console.log(`GoGa: 拦截到对 "${url}" 的 XHR POST 请求。尝试ECDH加密。`);
                
                // 使用ECDH加密替代原有的对称加密
                const gogaPayload = await buildECDHEncryptedPayload(body, originalContentType);
                console.log('GoGa: XHR 请求体已使用ECDH加密。');

                const finalBody = JSON.stringify(gogaPayload);
                
                // 显式设置 Content-Type 以确保后端正确识别为 JSON
                originalXhrSetRequestHeader.call(self, 'Content-Type', 'application/json;charset=UTF-8');

                console.log(`GoGa: 正在发送ECDH加密的 XHR 请求体到 "${url}"。`);
                
                // 保存原始回调函数
                const originalOnReadyStateChange = self.onreadystatechange;
                
                // 设置新的回调函数以处理响应解密
                self.onreadystatechange = function() {
                    // 先调用原始回调
                    if (originalOnReadyStateChange) {
                        originalOnReadyStateChange.call(self);
                    }
                    
                    // 当请求完成时，检查响应是否需要解密
                    if (self.readyState === XMLHttpRequest.DONE && self.status === 200) {
                        try {
                            const responseData = JSON.parse(self.responseText);
                            
                            // 如果响应包含ECDH加密标识，尝试解密
                            if (responseData.version === "1.0" && responseData.sessionId && 
                                responseData.encryptedData && responseData.encryptedIV) {
                                (async function() {
                                    try {
                                        const decryptedBody = await decryptECDHResponse(responseData);
                                        
                                        // 修改响应文本为解密后的内容
                                        Object.defineProperty(self, 'responseText', {
                                            value: decryptedBody,
                                            writable: false
                                        });
                                        
                                        // 如果有响应XML，也进行更新
                                        if (self.responseXML) {
                                            try {
                                                const parser = new DOMParser();
                                                const xmlDoc = parser.parseFromString(decryptedBody, 'application/xml');
                                                Object.defineProperty(self, 'responseXML', {
                                                    value: xmlDoc,
                                                    writable: false
                                                });
                                            } catch (e) {
                                                // 如果不是XML，忽略错误
                                            }
                                        }
                                        
                                        // 触发事件通知数据已解密
                                        const event = new CustomEvent('goga-response-decrypted', {
                                            detail: { original: responseData, decrypted: decryptedBody }
                                        });
                                        self.dispatchEvent(event);
                                    } catch (decryptError) {
                                        console.warn(`GoGa: XHR响应解密失败，返回原始响应:`, decryptError.message);
                                    }
                                })();
                            }
                        } catch (e) {
                            // 如果不是JSON，忽略解密
                        }
                    }
                };
                
                originalXhrSend.call(self, finalBody);

            } catch (e) {
                console.warn(`GoGa: 对 "${url}" 的 XHR 请求未加密。原因:`, e.message);
                originalXhrSend.apply(self, arguments);
            }
        })();
    };


    // Initialize ECDH session on page load
    document.addEventListener('DOMContentLoaded', () => {
        console.log('GoGa: DOM 内容已加载，正在初始化ECDH会话...');
        initializeECDHSession().catch(error => {
            console.warn('GoGa: ECDH会话初始化失败，将按需初始化。', error);
        });
    });

    // 导出GoGa API到全局命名空间，以便外部调用
    window.GoGa = {
        // ECDH密钥交换相关API
        generateECDHKeyPair,
        exportPublicKey,
        importPublicKey,
        computeSharedSecret,
        deriveKeys,
        
        // 会话管理API
        initializeECDHSession,
        ensureECDHSession,
        
        // 加密/解密API
        encryptData,
        decryptData,
        buildECDHEncryptedPayload,
        decryptECDHResponse,
        
        // 工具函数
        base64ToArrayBuffer,
        arrayBufferToBase64,
        
        // 缓存访问
        getSessionCache: () => ({ ...sessionCache })
    };

    console.log('GoGa 加密脚本 (Fetch & XHR 拦截器，支持ECDH密钥交换) 已加载并准备就绪。');

})();
