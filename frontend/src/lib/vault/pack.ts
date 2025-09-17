import { seal, open } from '../crypto/secretbox';

export type VaultItemPlain = {
    title: string;
    username: string;
    password: string;
    url?: string;
    notes?: string;
};

export type VaultItemEncrypted = {
    titleCipher: string;   titleNonce: string;
    usernameCipher: string; usernameNonce: string;
    passwordCipher: string; passwordNonce: string;
    url?: string;
    notesCipher?: string; notesNonce?: string;
};

export async function packItem(
    dek: CryptoKey,
    p: VaultItemPlain
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
    e: VaultItemEncrypted
): Promise<VaultItemPlain> {
    const title = await open(dek, e.titleCipher, e.titleNonce);
    const username = await open(dek, e.usernameCipher, e.usernameNonce);
    const password = await open(dek, e.passwordCipher, e.passwordNonce);
    const notes = e.notesCipher && e.notesNonce
        ? await open(dek, e.notesCipher, e.notesNonce)
        : undefined;
    return { title, username, password, url: e.url, notes };
}
