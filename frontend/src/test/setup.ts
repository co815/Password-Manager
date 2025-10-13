import '@testing-library/jest-dom/vitest';
import {vi} from 'vitest';

vi.mock('hash-wasm', () => ({
    argon2id: async () => new Uint8Array(32),
}));

if (typeof window !== 'undefined' && window.navigator?.userAgent.includes('happy-dom')) {
    const descriptor = Object.getOwnPropertyDescriptor(HTMLScriptElement.prototype, 'src');
    if (descriptor?.configurable) {
        Object.defineProperty(HTMLScriptElement.prototype, 'src', {
            configurable: true,
            get() {
                return this.getAttribute('data-src') ?? '';
            },
            set(value: string) {
                this.setAttribute('data-src', value);
            },
        });
    }

    const originalSetAttribute = HTMLScriptElement.prototype.setAttribute;
    HTMLScriptElement.prototype.setAttribute = function(name: string, value: string) {
        if (name.toLowerCase() === 'src') {
            this.src = value;
            return value;
        }
        return originalSetAttribute.call(this, name, value);
    };

    const originalGetAttribute = HTMLScriptElement.prototype.getAttribute;
    HTMLScriptElement.prototype.getAttribute = function(name: string) {
        if (name.toLowerCase() === 'src') {
            return this.src;
        }
        return originalGetAttribute.call(this, name);
    };
}