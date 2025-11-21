// GoGa Client-Side Encryption Script (Fetch Interceptor)
(function() {
    'use strict';

    // 密钥缓存，用于存储从网关获取的密钥、令牌和过期时间
    let keyCache = {
        key: null,
        token: null,
        expires: 0, // 过期时间戳 (ms)
    };
    // CACHE_DURATION_MS will now be dynamically calculated from server's TTL.
    // Client-side cache duration must be less than server-side key's TTL.

    // 保存原始的 fetch 函数
    const originalFetch = window.fetch;

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
        const keyResponse = await originalFetch('/goga/api/v1/key');
        if (!keyResponse.ok) {
            // 获取失败时，清空缓存以确保下次能重试
            keyCache = { key: null, token: null, expires: 0 };
            throw new Error('无法获取加密密钥。');
        }
        const { key, token, ttl } = await keyResponse.json();
        
        // Calculate client-side cache duration: 80% of server's TTL, with a minimum of 60 seconds (1 minute) if TTL is too small.
        // This ensures the client key expires before the server key, preventing decryption failures.
        const clientCacheDurationMs = (ttl * 1000 * 0.8) || (4 * 60 * 1000); // 80% of server TTL, or fallback to 4 minutes
        
        // Update cache
        keyCache = {
            key: key,
            token: token,
            expires: Date.now() + clientCacheDurationMs,
        };
        console.log('GoGa: New key fetched and cached.');
        return keyCache;
    }

    // 创建我们自己的 fetch 函数
    window.fetch = async function(...args) {
        const [url, options] = args;

        // 定义我们想要拦截的条件：
        // 1. 这是一个 API 请求 (可以根据需要调整, 例如排除 .js, .css 文件)
        // 2. options 存在, 并且 method 是 'POST'
        // 3. options.body 存在, 是一个字符串 (可能是 JSON)
        // 4. 请求不是发往 GoGa 自己的 key API
        const isApiPost = options && options.method && options.method.toUpperCase() === 'POST' &&
                          options.body && typeof options.body === 'string' &&
                          !url.toString().includes('/goga/api/v1/key');

        if (isApiPost) {
            try {
                // 确认 body 是一个有效的 JSON 字符串，否则我们不处理
                JSON.parse(options.body);

                console.log(`GoGa: Intercepted a POST request to "${url}". Attempting to encrypt body.`);

                // 1. 获取原始请求体和 Content-Type
                const originalContentType = (options.headers && options.headers['Content-Type']) || 'application/json';
                const bodyStr = options.body;

                // 2. 构建二进制载荷: [1-byte length][Content-Type][Body]
                const encoder = new TextEncoder();
                const contentTypeBytes = encoder.encode(originalContentType);
                const bodyBytes = encoder.encode(bodyStr);

                if (contentTypeBytes.length > 255) {
                    throw new Error('Content-Type header is too long (max 255 bytes).');
                }

                const payloadBuffer = new Uint8Array(1 + contentTypeBytes.length + bodyBytes.length);
                payloadBuffer[0] = contentTypeBytes.length; // 写入1字节的长度
                payloadBuffer.set(contentTypeBytes, 1); // 写入 Content-Type
                payloadBuffer.set(bodyBytes, 1 + contentTypeBytes.length); // 写入 Body

                // 3. 从缓存或服务器获取密钥和令牌
                const { key, token } = await getEncryptionKey();

                // 4. 加密二进制载荷
                const encryptedData = await encryptData(key, payloadBuffer.buffer);
                console.log('GoGa: Binary payload encrypted.');

                // 5. 构建用于网关的最终载荷
                const gogaPayload = {
                    token: token,
                    encrypted: encryptedData,
                };

                // 6. 复制并修改原始的请求 options
                const newOptions = { ...options };
                newOptions.body = JSON.stringify(gogaPayload);
                
                // 7. 确保发往网关的请求 Content-Type 是 application/json
                newOptions.headers = { ...newOptions.headers, 'Content-Type': 'application/json' };

                console.log(`GoGa: Sending encrypted payload to "${url}".`);
                // 8. 使用修改后的 options 调用原始的 fetch 函数
                return originalFetch(url, newOptions);

            } catch (e) {
                // 如果 body 不是 JSON，或加密过程中出现任何错误，则不拦截，直接传递原始请求
                console.warn(`GoGa: Request to "${url}" was not encrypted. Reason:`, e.message);
                return originalFetch(...args);
            }
        }

        // 对于所有其他不满足条件的请求，直接调用原始的 fetch 函数
        return originalFetch(...args);
    };

    // 在页面加载后立即预取密钥，以优化首次加密请求的用户体验
    document.addEventListener('DOMContentLoaded', () => {
        console.log('GoGa: DOM content loaded, pre-fetching encryption key...');
        getEncryptionKey().catch(error => {
            // 预取是优化项，失败了不应阻塞页面。后续的加密请求会自动再次尝试获取。
            console.warn('GoGa: Key pre-fetching failed, will fetch on demand.', error);
        });
    });

    console.log('GoGa crypto script (Fetch Interceptor) loaded and ready.');

})();