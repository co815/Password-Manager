import { deriveKEK } from './argon2';
import { aesGenKey, aesExportRaw, aesGcmEncrypt } from './aesgcm';
import { toB64 } from './codec';

export async function createAccountMaterial(masterPassword: string){
    const saltClientRaw = crypto.getRandomValues(new Uint8Array(16));
    const saltClient = toB64(saltClientRaw);
    const KEK = await deriveKEK(masterPassword, saltClient);
    const DEK = await aesGenKey();
    const rawDEK = new Uint8Array(await aesExportRaw(DEK));

    const { ct, iv } = await aesGcmEncrypt(KEK, rawDEK);
    const dekEncrypted = toB64(ct);
    const dekNonce = toB64(iv);

    return { saltClient, dekEncrypted, dekNonce };
}

export async function encryptDekWithKek(dek: CryptoKey, kek: CryptoKey) {
    const rawDek = new Uint8Array(await aesExportRaw(dek));
    const { ct, iv } = await aesGcmEncrypt(kek, rawDek);
    return {
        dekEncrypted: toB64(ct),
        dekNonce: toB64(iv)
    };
}
