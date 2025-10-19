const BASE64_PAD = '=';

declare const Buffer: {
    from(input: string, encoding?: string): { toString(encoding?: string): string };
} | undefined;

function normalizeBase64(input: string): string {
    const sanitized = input.replace(/-/g, '+').replace(/_/g, '/').trim();
    const padLength = sanitized.length % 4;
    if (padLength === 0) return sanitized;
    if (padLength === 2) return `${sanitized}${BASE64_PAD}${BASE64_PAD}`;
    if (padLength === 3) return `${sanitized}${BASE64_PAD}`;
    return sanitized;
}

function base64ToBinary(input: string): string {
    const normalized = normalizeBase64(input);
    if (typeof atob === 'function') {
        return atob(normalized);
    }
    if (typeof Buffer !== 'undefined') {
        return Buffer.from(normalized, 'base64').toString('binary');
    }
    throw new Error('Base64 decoding not supported in this environment');
}

function binaryToBase64(input: string): string {
    if (typeof btoa === 'function') {
        return btoa(input);
    }
    if (typeof Buffer !== 'undefined') {
        return Buffer.from(input, 'binary').toString('base64');
    }
    throw new Error('Base64 encoding not supported in this environment');
}

function base64ToUint8Array(value: string): Uint8Array {
    const binary = base64ToBinary(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    let binary = '';
    bytes.forEach((byte) => {
        binary += String.fromCharCode(byte);
    });
    return binaryToBase64(binary);
}

function cloneClientOutputs(
    extensions: AuthenticationExtensionsClientOutputs | undefined,
): AuthenticationExtensionsClientOutputs | undefined {
    if (!extensions) return extensions;
    return JSON.parse(JSON.stringify(extensions)) as AuthenticationExtensionsClientOutputs;
}

function normalizeAppIdExtension(value: unknown): string | undefined {
    if (typeof value !== 'string') {
        return undefined;
    }
    const trimmed = value.trim();
    if (!trimmed) {
        return undefined;
    }
    try {
        const parsed = new URL(trimmed);
        const isHttps = parsed.protocol === 'https:';
        const isLocalHttp = parsed.protocol === 'http:'
            && (parsed.hostname === 'localhost'
                || parsed.hostname === '127.0.0.1'
                || parsed.hostname === '[::1]');
        if (!isHttps && !isLocalHttp) {
            return undefined;
        }
        return parsed.toString();
    } catch {
        return undefined;
    }
}

function cloneClientInputs(
    extensions: AuthenticationExtensionsClientInputs | undefined,
): AuthenticationExtensionsClientInputs | undefined {
    if (!extensions) return extensions;
    const clone = JSON.parse(JSON.stringify(extensions)) as AuthenticationExtensionsClientInputs;
    const maybeNormalize = (key: 'appid' | 'appidExclude') => {
        if (key in clone) {
            const normalized = normalizeAppIdExtension(clone[key]);
            if (normalized) {
                clone[key] = normalized;
            } else {
                delete clone[key];
            }
        }
    };
    maybeNormalize('appid');
    maybeNormalize('appidExclude');
    return Object.keys(clone).length > 0 ? clone : undefined;
}

export interface PublicKeyCredentialUserEntityJSON extends Omit<PublicKeyCredentialUserEntity, 'id'> {
    id: string;
}

export interface PublicKeyCredentialDescriptorJSON extends Omit<PublicKeyCredentialDescriptor, 'id'> {
    id: string;
}

export interface PublicKeyCredentialCreationOptionsJSON extends Omit<PublicKeyCredentialCreationOptions, 'challenge' | 'user' | 'excludeCredentials' | 'extensions'> {
    challenge: string;
    user: PublicKeyCredentialUserEntityJSON;
    excludeCredentials?: PublicKeyCredentialDescriptorJSON[];
    extensions?: AuthenticationExtensionsClientInputs;
}

export interface PublicKeyCredentialRequestOptionsJSON extends Omit<PublicKeyCredentialRequestOptions, 'challenge' | 'allowCredentials' | 'extensions'> {
    challenge: string;
    allowCredentials?: PublicKeyCredentialDescriptorJSON[];
    extensions?: AuthenticationExtensionsClientInputs;
}

export interface WebAuthnAttestationCredentialJSON {
    id: string;
    rawId: string;
    type: PublicKeyCredentialType;
    authenticatorAttachment?: AuthenticatorAttachment | null;
    clientExtensionResults: AuthenticationExtensionsClientOutputs;
    response: {
        clientDataJSON: string;
        attestationObject: string;
        transports?: AuthenticatorTransport[];
    };
}

export interface WebAuthnAssertionCredentialJSON {
    id: string;
    rawId: string;
    type: PublicKeyCredentialType;
    authenticatorAttachment?: AuthenticatorAttachment | null;
    clientExtensionResults: AuthenticationExtensionsClientOutputs;
    response: {
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
        userHandle?: string | null;
    };
}

function decodeCredentialDescriptors(descriptors?: PublicKeyCredentialDescriptorJSON[]): PublicKeyCredentialDescriptor[] | undefined {
    return descriptors?.map((descriptor) => ({
        ...descriptor,
        id: base64ToUint8Array(descriptor.id),
    }));
}

export function decodeCreationOptions(options: PublicKeyCredentialCreationOptionsJSON): PublicKeyCredentialCreationOptions {
    return {
        ...options,
        challenge: base64ToUint8Array(options.challenge),
        user: {
            ...options.user,
            id: base64ToUint8Array(options.user.id),
        },
        excludeCredentials: decodeCredentialDescriptors(options.excludeCredentials),
        extensions: cloneClientInputs(options.extensions),
    };
}

export function decodeRequestOptions(options: PublicKeyCredentialRequestOptionsJSON): PublicKeyCredentialRequestOptions {
    return {
        ...options,
        challenge: base64ToUint8Array(options.challenge),
        allowCredentials: decodeCredentialDescriptors(options.allowCredentials),
        extensions: cloneClientInputs(options.extensions),
    };
}

function isAttestationResponse(response: AuthenticatorResponse): response is AuthenticatorAttestationResponse {
    return typeof (response as AuthenticatorAttestationResponse).getTransports === 'function'
        && 'attestationObject' in response;
}

function isAssertionResponse(response: AuthenticatorResponse): response is AuthenticatorAssertionResponse {
    return 'signature' in response && 'authenticatorData' in response;
}

export function attestationToJSON(credential: PublicKeyCredential): WebAuthnAttestationCredentialJSON {
    if (!isAttestationResponse(credential.response)) {
        throw new Error('Unexpected credential response type for attestation');
    }

    const response = credential.response;
    const transports = typeof response.getTransports === 'function' ? response.getTransports() : undefined;

    return {
        id: credential.id,
        rawId: arrayBufferToBase64(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
        clientExtensionResults: cloneClientOutputs(credential.getClientExtensionResults()),
        response: {
            clientDataJSON: arrayBufferToBase64(response.clientDataJSON),
            attestationObject: arrayBufferToBase64(response.attestationObject),
            transports: transports && transports.length > 0 ? [...transports] : undefined,
        },
    };
}

export function assertionToJSON(credential: PublicKeyCredential): WebAuthnAssertionCredentialJSON {
    if (!isAssertionResponse(credential.response)) {
        throw new Error('Unexpected credential response type for assertion');
    }

    const response = credential.response;
    const userHandle = response.userHandle;

    return {
        id: credential.id,
        rawId: arrayBufferToBase64(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment ?? undefined,
        clientExtensionResults: cloneClientOutputs(credential.getClientExtensionResults()),
        response: {
            clientDataJSON: arrayBufferToBase64(response.clientDataJSON),
            authenticatorData: arrayBufferToBase64(response.authenticatorData),
            signature: arrayBufferToBase64(response.signature),
            userHandle: userHandle ? arrayBufferToBase64(userHandle) : undefined,
        },
    };
}

export function isWebAuthnSupported(): boolean {
    if (typeof window === 'undefined' || typeof navigator === 'undefined') {
        return false;
    }
    return typeof window.PublicKeyCredential !== 'undefined'
        && typeof navigator.credentials !== 'undefined'
        && typeof navigator.credentials.create === 'function'
        && typeof navigator.credentials.get === 'function';
}
