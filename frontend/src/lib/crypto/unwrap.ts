export const fromB64 = (s: string) =>
    Uint8Array.from(atob(s), c => c.charCodeAt(0));

export async function unwrapDEK(
    kek: CryptoKey,
    dekEncryptedB64: string,
    dekNonceB64: string
): Promise<CryptoKey> {
    const iv = fromB64(dekNonceB64);
    const ct = fromB64(dekEncryptedB64);
    const dekRaw = new Uint8Array(
        await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kek, ct)
    );
    return crypto.subtle.importKey(
        'raw',
        dekRaw,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
    );
}

export { unwrapDEK as unwrapDek };
