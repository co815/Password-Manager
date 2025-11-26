export async function aesGcmEncrypt(key: CryptoKey, data: Uint8Array): Promise<{ ct: ArrayBuffer, iv: Uint8Array }> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return { ct, iv };
}

export async function aesGcmDecrypt(key: CryptoKey, ct: ArrayBuffer, iv: Uint8Array): Promise<ArrayBuffer> {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
}

export async function aesGenKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function aesExportRaw(key: CryptoKey): Promise<ArrayBuffer> {
    return crypto.subtle.exportKey('raw', key);
}
