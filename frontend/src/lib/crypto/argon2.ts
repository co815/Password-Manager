import { argon2id } from 'hash-wasm';

function fromB64(s: string) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function toB64(bytes: ArrayBuffer | Uint8Array) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    return btoa(String.fromCharCode(...u8));
}

export async function deriveKEK(masterPassword: string, saltB64: string): Promise<CryptoKey> {
    const salt = fromB64(saltB64);
    const keyBytes = await argon2id({
        password: masterPassword,
        salt,
        iterations: 3,
        memorySize: 64 * 1024,
        parallelism: 1,
        hashLength: 32,
        outputType: 'binary',
    });
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function makeVerifier(email: string, mp: string, saltB64: string): Promise<string> {
    const salt = fromB64(saltB64);
    const digest = await argon2id({
        password: `login|${email}|${mp}`,
        salt,
        iterations: 3,
        memorySize: 64 * 1024,
        parallelism: 1,
        hashLength: 32,
        outputType: 'binary',
    });
    return toB64(digest);
}
