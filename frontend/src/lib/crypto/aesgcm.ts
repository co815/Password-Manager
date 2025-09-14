export function rand(n = 12) {
    return crypto.getRandomValues(new Uint8Array(n));
}

export function b64(a: ArrayBuffer | Uint8Array) {
    const u8 = a instanceof Uint8Array ? a : new Uint8Array(a);
    return btoa(String.fromCharCode(...u8));
}

export async function aesGenKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}

export async function aesExportRaw(k: CryptoKey) {
    return crypto.subtle.exportKey('raw', k);
}

export async function enc(key: CryptoKey, data: Uint8Array) {
    const iv = rand(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
    return { ct: b64(ct), iv: b64(iv) };
}

export async function dec(key: CryptoKey, ctB64: string, ivB64: string) {
    const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
    const ct = Uint8Array.from(atob(ctB64), c => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new Uint8Array(pt);
}
