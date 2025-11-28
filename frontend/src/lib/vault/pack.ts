import {seal, open} from '../crypto/secretbox';

type RecordLike = Record<string, unknown>;

export type VaultItemPlain = {
    title: string;
    username: string;
    password: string;
    url?: string;
    notes?: string;
};

export type VaultItemEncrypted = {
    titleCipher: string; titleNonce: string;
    usernameCipher: string; usernameNonce: string;
    passwordCipher: string; passwordNonce: string;
    url?: string;
    notesCipher?: string; notesNonce?: string;
};

export async function packItem(
    dek: CryptoKey,
    p: VaultItemPlain,
): Promise<VaultItemEncrypted> {
    const t = await seal(dek, p.title);
    const u = await seal(dek, p.username);
    const pw = await seal(dek, p.password);

    const out: VaultItemEncrypted = {
        titleCipher: t.cipher, titleNonce: t.nonce,
        usernameCipher: u.cipher, usernameNonce: u.nonce,
        passwordCipher: pw.cipher, passwordNonce: pw.nonce,
    };
    if (p.url) out.url = p.url;

    if (p.notes && p.notes.trim()) {
        const n = await seal(dek, p.notes);
        out.notesCipher = n.cipher;
        out.notesNonce = n.nonce;
    }
    return out;
}

export async function unpackItem(
    dek: CryptoKey,
    e: VaultItemEncrypted,
): Promise<VaultItemPlain> {
    const title = await open(dek, e.titleCipher, e.titleNonce);
    const username = await open(dek, e.usernameCipher, e.usernameNonce);
    const password = await open(dek, e.passwordCipher, e.passwordNonce);
    const notes = e.notesCipher && e.notesNonce
        ? await open(dek, e.notesCipher, e.notesNonce)
        : undefined;
    return {title, username, password, url: e.url, notes};
}

export type VaultCredentialPlain = {
    id: string;
    name: string;
    username: string;
    password: string;
    url?: string;
    collections?: string[];
};

export type VaultCredentialEncrypted = {
    id: string;
    nameCipher: string; nameNonce: string;
    usernameCipher: string; usernameNonce: string;
    passwordCipher: string; passwordNonce: string;
    urlCipher?: string; urlNonce?: string;
    collections?: string[];
};

export type VaultCredentialExport = {
    kind: typeof VAULT_EXPORT_KIND;
    version: typeof VAULT_EXPORT_VERSION;
    exportedAt: string;
    items: VaultCredentialEncrypted[];
};

export const VAULT_EXPORT_KIND = 'pmvault';
export const VAULT_EXPORT_VERSION = 1;

const isRecordLike = (value: unknown): value is RecordLike => (
    typeof value === 'object' && value !== null && !Array.isArray(value)
);

const assertString = (value: unknown, message: string): string => {
    if (typeof value !== 'string' || !value) {
        throw new Error(message);
    }
    return value;
};

export async function packCredentials(
    dek: CryptoKey,
    credentials: ReadonlyArray<VaultCredentialPlain>,
): Promise<VaultCredentialExport> {
    const items: VaultCredentialEncrypted[] = [];
    for (const cred of credentials) {
        const name = await seal(dek, cred.name ?? '');
        const username = await seal(dek, cred.username ?? '');
        const password = await seal(dek, cred.password ?? '');
        const item: VaultCredentialEncrypted = {
            id: cred.id,
            nameCipher: name.cipher, nameNonce: name.nonce,
            usernameCipher: username.cipher, usernameNonce: username.nonce,
            passwordCipher: password.cipher, passwordNonce: password.nonce,
            collections: cred.collections,
        };

        if (cred.url && cred.url.trim()) {
            const url = await seal(dek, cred.url.trim());
            item.urlCipher = url.cipher;
            item.urlNonce = url.nonce;
        }

        items.push(item);
    }

    return {
        kind: VAULT_EXPORT_KIND,
        version: VAULT_EXPORT_VERSION,
        exportedAt: new Date().toISOString(),
        items,
    };
}

export function parseVaultExport(raw: string): VaultCredentialExport {
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        throw new Error('Vault file is not valid JSON.');
    }

    if (!isRecordLike(parsed)) {
        throw new Error('Vault file structure is invalid.');
    }

    if (parsed.kind !== VAULT_EXPORT_KIND) {
        throw new Error('Unrecognized vault file.');
    }

    if (parsed.version !== VAULT_EXPORT_VERSION) {
        throw new Error('Unsupported vault export version.');
    }

    if (!Array.isArray(parsed.items)) {
        throw new Error('Vault file is missing credential data.');
    }

    const items: VaultCredentialEncrypted[] = parsed.items.map((item) => {
        if (!isRecordLike(item)) {
            throw new Error('Invalid credential entry in vault file.');
        }

        const id = assertString(item.id, 'Credential entry is missing an id.');
        const nameCipher = assertString(item.nameCipher, 'Credential entry missing encrypted name.');
        const nameNonce = assertString(item.nameNonce, 'Credential entry missing name nonce.');
        const usernameCipher = assertString(item.usernameCipher, 'Credential entry missing encrypted username.');
        const usernameNonce = assertString(item.usernameNonce, 'Credential entry missing username nonce.');
        const passwordCipher = assertString(item.passwordCipher, 'Credential entry missing encrypted password.');
        const passwordNonce = assertString(item.passwordNonce, 'Credential entry missing password nonce.');

        let urlCipher: string | undefined;
        let urlNonce: string | undefined;
        if ('urlCipher' in item || 'urlNonce' in item) {
            urlCipher = assertString(item.urlCipher, 'Credential entry missing encrypted URL.');
            urlNonce = assertString(item.urlNonce, 'Credential entry missing URL nonce.');
        }

        const collections = Array.isArray(item.collections) ? item.collections.map(String) : undefined;

        return {
            id,
            nameCipher,
            nameNonce,
            usernameCipher,
            usernameNonce,
            passwordCipher,
            passwordNonce,
            urlCipher,
            urlNonce,
            collections,
        } satisfies VaultCredentialEncrypted;
    });

    return {
        kind: VAULT_EXPORT_KIND,
        version: VAULT_EXPORT_VERSION,
        exportedAt: typeof parsed.exportedAt === 'string' ? parsed.exportedAt : new Date().toISOString(),
        items,
    };
}

export async function unpackCredentials(
    dek: CryptoKey,
    exportData: VaultCredentialExport,
): Promise<VaultCredentialPlain[]> {
    const result: VaultCredentialPlain[] = [];
    for (const item of exportData.items) {
        const name = await open(dek, item.nameCipher, item.nameNonce);
        const username = await open(dek, item.usernameCipher, item.usernameNonce);
        const password = await open(dek, item.passwordCipher, item.passwordNonce);
        const url = item.urlCipher && item.urlNonce
            ? await open(dek, item.urlCipher, item.urlNonce)
            : undefined;

        result.push({
            id: item.id,
            name,
            username,
            password,
            url,
            collections: item.collections,
        });
    }

    return result;
}

export async function serializeVaultCredentials(
    dek: CryptoKey,
    credentials: ReadonlyArray<VaultCredentialPlain>,
): Promise<string> {
    const payload = await packCredentials(dek, credentials);
    return JSON.stringify(payload, null, 2);
}

export async function deserializeVaultCredentials(
    dek: CryptoKey,
    raw: string,
): Promise<VaultCredentialPlain[]> {
    const parsed = parseVaultExport(raw);
    return unpackCredentials(dek, parsed);
}
