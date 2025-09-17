import { utf8, str, toB64, fromB64 } from './codec';

export async function seal(
    dek: CryptoKey,
    plaintext: string
): Promise<{ cipher: string; nonce: string }> {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const pt = utf8(plaintext);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dek, pt);
    return { cipher: toB64(ct), nonce: toB64(iv) };
}

export async function open(
    dek: CryptoKey,
    cipherB64: string,
    nonceB64: string
): Promise<string> {
    const iv = fromB64(nonceB64);
    const ct = fromB64(cipherB64);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, dek, ct);
    return str(pt);
}
