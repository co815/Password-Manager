import { deriveKey } from '../crypto';

function fromB64(s: string) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function toB64(bytes: ArrayBuffer | Uint8Array) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    return btoa(String.fromCharCode(...u8));
}

export async function deriveKEK(masterPassword: any, saltB64: string): Promise<CryptoKey> {
    const salt = fromB64(saltB64);
    const keyBytes = await deriveKey(masterPassword, salt);
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
