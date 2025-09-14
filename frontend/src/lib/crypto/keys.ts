import { deriveKEK } from './argon2';
import { aesGenKey, aesExportRaw, enc, b64 } from './aesgcm';

export async function createAccountMaterial(masterPassword: string){
    const saltClient = b64(crypto.getRandomValues(new Uint8Array(16)));
    const KEK = await deriveKEK(masterPassword, saltClient);
    const DEK = await aesGenKey();
    const rawDEK = new Uint8Array(await aesExportRaw(DEK));
    const { ct: dekEncrypted, iv: dekNonce } = await enc(KEK, rawDEK);
    return { saltClient, dekEncrypted, dekNonce };
}
