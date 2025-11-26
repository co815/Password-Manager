import { aesGcmEncrypt, aesGcmDecrypt } from './aesgcm';

export async function encryptVault(key: CryptoKey, vaultData: any): Promise<any> {
    const serialized = JSON.stringify(vaultData);
    const plaintext = new TextEncoder().encode(serialized);
    const { ct, iv } = await aesGcmEncrypt(key, plaintext);
    return {
        ct: Buffer.from(ct).toString('base64'),
        iv: Buffer.from(iv).toString('base64'),
    };
}

export async function decryptVault(key: CryptoKey, encryptedVault: any): Promise<any> {
    const ct = Buffer.from(encryptedVault.ct, 'base64');
    const iv = Buffer.from(encryptedVault.iv, 'base64');
    const decrypted = await aesGcmDecrypt(key, ct, iv);
    const serialized = new TextDecoder().decode(decrypted);
    return JSON.parse(serialized);
}
