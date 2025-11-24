/**
 * Copyright (c) 2025 wangke <464829928@qq.com>
 *
 * This software is released under the AGPL-3.0 license.
 * For more details, see the LICENSE file in the root directory.
 */
// GoGa Client-Side Encryption Script (Fetch & XHR Interceptor)
(function() {
    'use strict';

    // First, check for a secure context.
    if (!window.crypto || !window.crypto.subtle) {
        console.error(
            'GoGa Encryption Aborted: This script requires a secure context (HTTPS or localhost). ' +
            'The window.crypto.subtle API is not available, and encryption has been disabled. ' +
            'Please serve your application over HTTPS or use localhost.'
        );
        return; // Stop execution if crypto is not available.
    }


    // 密钥缓存，用于存储从网关获取的密钥、令牌和过期时间
    let keyCache = {
        key: null,
        token: null,
        expires: 0, // 过期时间戳 (ms)
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

    /**
     * 使用 AES-GCM 加密数据。
     * @param {string} base64Key - Base64 编码的加密密钥。
     * @param {ArrayBuffer} dataToEncrypt - 要加密的 ArrayBuffer 数据。
     * @returns {Promise<string>} - 返回一个 Promise，解析为 Base64 编码的加密数据 (iv + ciphertext)。
     */
    async function encryptData(base64Key, dataToEncrypt) {
        const keyBuffer = base64ToArrayBuffer(base64Key);
        const cryptoKey = await window.crypto.subtle.importKey(
            'raw',
            keyBuffer,
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );
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
     * 获取用于加密的密钥和令牌，优先从缓存中读取。
     * 如果缓存为空或已过期，则从服务器获取新密钥并更新缓存。
     * @returns {Promise<{key: string, token: string}>}
     */
    async function getEncryptionKey() {
        const now = Date.now();
        if (keyCache.key && keyCache.token && now < keyCache.expires) {
            console.log('GoGa: Using cached key.');
            return keyCache;
        }

        console.log('GoGa: Cache empty or expired. Fetching new key...');
        // Use originalFetch to avoid interception loop
        const keyResponse = await originalFetch('/goga/api/v1/key');
        if (!keyResponse.ok) {
            keyCache = { key: null, token: null, expires: 0 };
            throw new Error('无法获取加密密钥。');
        }
        const { key, token, ttl } = await keyResponse.json();
        
        const clientCacheDurationMs = (ttl * 1000 * 0.8) || (4 * 60 * 1000);
        
        keyCache = {
            key: key,
            token: token,
            expires: Date.now() + clientCacheDurationMs,
        };
        console.log('GoGa: New key fetched and cached.');
        return keyCache;
    }
    
    /**
     * Helper function to build the encrypted payload.
     * @param {string} bodyStr The original request body string.
     * @param {string} originalContentType The original Content-Type header.
     * @returns {Promise<object>} The final payload for the gateway.
     */
    async function buildEncryptedPayload(bodyStr, originalContentType) {
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

        const { key, token } = await getEncryptionKey();
        const encryptedData = await encryptData(key, payloadBuffer.buffer);

        return {
            token: token,
            encrypted: encryptedData,
        };
    }

    // Intercept fetch
    window.fetch = async function(...args) {
        const [url, options] = args;

        const isApiPost = options && options.method && options.method.toUpperCase() === 'POST' &&
                          options.body && typeof options.body === 'string' &&
                          !url.toString().includes('/goga/api/v1/key');

        if (isApiPost) {
            try {
                const originalContentType = (options.headers && (options.headers['Content-Type'] || options.headers['content-type'])) || 'application/json';
                const isJsonRequest = originalContentType.includes('application/json');

                if (!isJsonRequest) {
                    console.log(`GoGa: fetch request to "${url}" has non-JSON Content-Type (${originalContentType}). Bypassing encryption.`);
                    return originalFetch(...args);
                }

                JSON.parse(options.body); // Ensure body is valid JSON
                console.log(`GoGa: Intercepted a fetch POST request to "${url}". Attempting to encrypt.`);
                
                const gogaPayload = await buildEncryptedPayload(options.body, originalContentType);
                console.log('GoGa: fetch payload encrypted.');

                const newOptions = { ...options };
                newOptions.body = JSON.stringify(gogaPayload);
                newOptions.headers = { ...newOptions.headers, 'Content-Type': 'application/json;charset=UTF-8' };

                console.log(`GoGa: Sending encrypted fetch payload to "${url}".`);
                return originalFetch(url, newOptions);

            } catch (e) {
                console.warn(`GoGa: fetch request to "${url}" was not encrypted. Reason:`, e.message);
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
            !url.toString().includes('/goga/api/v1/key');

        if (!isApiPost) {
            return originalXhrSend.apply(self, arguments);
        }

        (async function() {
            try {
                const originalContentType = self._goga_headers['content-type'] || 'application/json';
                const isJsonRequest = originalContentType.includes('application/json');

                if (!isJsonRequest) {
                    console.log(`GoGa: XHR request to "${url}" has non-JSON Content-Type (${originalContentType}). Bypassing encryption.`);
                    originalXhrSend.apply(self, arguments);
                    return;
                }

                JSON.parse(body); // Ensure body is valid JSON
                console.log(`GoGa: Intercepted an XHR POST request to "${url}". Attempting to encrypt.`);
                
                const gogaPayload = await buildEncryptedPayload(body, originalContentType);
                console.log('GoGa: XHR payload encrypted.');

                const finalBody = JSON.stringify(gogaPayload);
                
                console.log(`GoGa: Sending encrypted XHR payload to "${url}".`);
                originalXhrSend.call(self, finalBody);

            } catch (e) {
                console.warn(`GoGa: XHR request to "${url}" was not encrypted. Reason:`, e.message);
                originalXhrSend.apply(self, arguments);
            }
        })();
    };


    // Pre-fetch key on page load
    document.addEventListener('DOMContentLoaded', () => {
        console.log('GoGa: DOM content loaded, pre-fetching encryption key...');
        getEncryptionKey().catch(error => {
            console.warn('GoGa: Key pre-fetching failed, will fetch on demand.', error);
        });
    });

    console.log('GoGa crypto script (Fetch & XHR Interceptor) loaded and ready.');

})();
