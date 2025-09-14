declare module 'argon2-browser' {
    export enum ArgonType { Argon2d = 0, Argon2i = 1, Argon2id = 2 }
    export interface HashOptions {
        pass: string | Uint8Array;
        salt: Uint8Array;
        time?: number;
        mem?: number;
        parallelism?: number;
        hashLen?: number;
        type?: ArgonType;
    }
    export function hash(opts: HashOptions): Promise<{ hash: Uint8Array }>;
}
