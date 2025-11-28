import { argon2id } from 'hash-wasm';

export async function deriveKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
    return await argon2id({
        password,
        salt,
        parallelism: 1,
        memorySize: 65536,
        iterations: 3,
        hashLength: 32,
        outputType: 'binary',
    });
}

export async function generateLoginHash(password: string, salt: Uint8Array): Promise<string> {
    return await argon2id({
        password,
        salt,
        parallelism: 1,
        memorySize: 65536,
        iterations: 3,
        hashLength: 32,
        outputType: 'hex',
    });
}
