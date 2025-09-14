import { hash, ArgonType } from 'argon2-browser';

function b64(bytes: ArrayBuffer | Uint8Array) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    return btoa(String.fromCharCode(...u8));
}

export async function deriveKEK(masterPassword: string, saltB64: string): Promise<CryptoKey> {
    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    const { hash: keyBytes } = await hash({
        pass: masterPassword,
        salt,
        type: ArgonType.Argon2id,
        time: 3,
        mem: 64 * 1024,
        parallelism: 1,
        hashLen: 32,
    });
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt','decrypt']);
}

export async function makeVerifier(email: string, mp: string, saltB64: string): Promise<string> {
    const salt = Uint8Array.from(atob(saltB64), c => c.charCodeAt(0));
    const { hash: digest } = await hash({
        pass: `login|${email}|${mp}`,
        salt,
        type: ArgonType.Argon2id,
        time: 3,
        mem: 64 * 1024,
        parallelism: 1,
        hashLen: 32,
    });
    return b64(digest);
}
