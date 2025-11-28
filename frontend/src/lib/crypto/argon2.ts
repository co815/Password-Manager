import { deriveKey, generateLoginHash } from './hasher';
import { fromB64 } from './codec';

export async function deriveKEK(masterPassword: string, saltB64: string): Promise<CryptoKey> {
    const salt = fromB64(saltB64);
    const keyBytes = await deriveKey(masterPassword, salt);
    return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function makeVerifier(_email: string, password: string, saltB64: string): Promise<string> {
    return generateLoginHash(password, fromB64(saltB64));
}
