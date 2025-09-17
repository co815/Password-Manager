const enc = new TextEncoder();
const dec = new TextDecoder();

export function utf8(s: string): Uint8Array {
    return enc.encode(s);
}

export function str(b: ArrayBuffer | Uint8Array): string {
    const view = b instanceof Uint8Array ? b : new Uint8Array(b);
    return dec.decode(view);
}

export function toB64(b: ArrayBuffer | Uint8Array): string {
    const view = b instanceof Uint8Array ? b : new Uint8Array(b);
    let s = "";
    for (let i = 0; i < view.length; i++) s += String.fromCharCode(view[i]);
    return btoa(s);
}

export function fromB64(s: string): Uint8Array {
    return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
