const STORAGE_PREFIX = 'pm-dek:';

const encode = (buffer: ArrayBuffer | Uint8Array) => {
    const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    view.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });
    return btoa(binary);
};

const decode = (payload: string) => {
    const binary = atob(payload);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
};

function storageAvailable(): Storage | null {
    try {
        if (typeof window === 'undefined' || typeof window.localStorage === 'undefined') {
            return null;
        }
        const {localStorage} = window;
        const testKey = `${STORAGE_PREFIX}__test`;
        localStorage.setItem(testKey, '1');
        localStorage.removeItem(testKey);
        return localStorage;
    } catch {
        return null;
    }
}

export async function rememberDek(userId: string, dek: CryptoKey): Promise<void> {
    const storage = storageAvailable();
    if (!storage || !userId) return;
    try {
        const raw = await crypto.subtle.exportKey('raw', dek);
        storage.setItem(`${STORAGE_PREFIX}${userId}`, encode(raw));
    } catch (error) {
        if (import.meta.env.DEV) {
            console.warn('Failed to persist data encryption key for reuse', error);
        }
    }
}

export async function restoreDek(userId: string): Promise<CryptoKey | null> {
    const storage = storageAvailable();
    if (!storage || !userId) return null;
    const payload = storage.getItem(`${STORAGE_PREFIX}${userId}`);
    if (!payload) return null;
    try {
        const raw = decode(payload);
        return await crypto.subtle.importKey('raw', raw, {name: 'AES-GCM'}, true, ['encrypt', 'decrypt']);
    } catch (error) {
        if (import.meta.env.DEV) {
            console.warn('Failed to restore persisted data encryption key', error);
        }
        try {
            storage.removeItem(`${STORAGE_PREFIX}${userId}`);
        } catch {
            // Ignore storage removal errors.
        }
        return null;
    }
}

export function forgetDek(userId: string): void {
    const storage = storageAvailable();
    if (!storage || !userId) return;
    try {
        storage.removeItem(`${STORAGE_PREFIX}${userId}`);
    } catch {
        // Ignore storage removal errors.
    }
}

export function forgetAllDek(): void {
    const storage = storageAvailable();
    if (!storage) return;
    const toRemove: string[] = [];
    for (let i = 0; i < storage.length; i += 1) {
        const key = storage.key(i);
        if (key && key.startsWith(STORAGE_PREFIX)) {
            toRemove.push(key);
        }
    }
    toRemove.forEach((key) => {
        try {
            storage.removeItem(key);
        } catch {
            // Ignore removal errors.
        }
    });
}
