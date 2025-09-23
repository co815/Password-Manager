const API_ORIGIN = import.meta.env.VITE_API_ORIGIN ?? 'https://localhost:8443';


export interface PublicUser {
    id: string;
    email: string;
    username: string;
    saltClient: string;
    dekEncrypted: string;
    dekNonce: string;
}

export const AUTH_CLEARED_EVENT = 'auth-cleared';

function emitAuthCleared() {
    if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent(AUTH_CLEARED_EVENT));
    }
}
function safeJson(s: string) { try { return JSON.parse(s); } catch { return null; } }

function mergeHeaders(init: RequestInit): Headers {
    const h = new Headers(init.headers || {});
    if (!h.has('Content-Type')) h.set('Content-Type', 'application/json');
    return h;
}

interface RequestOptions {
    suppressAuthCleared?: boolean;
}

export class ApiError extends Error {
    status: number;
    data: unknown;

    constructor(message: string, status: number, data: unknown) {
        super(message);
        this.name = 'ApiError';
        this.status = status;
        this.data = data;
    }
}

async function req<T>(
    path: string,
    init: RequestInit = {},
    options: RequestOptions = {},
): Promise<T> {
    const res = await fetch(`${API_ORIGIN}/api${path}`, {
        ...init,
        headers: mergeHeaders(init),
        credentials: 'include',
    });

    if (res.status === 204) return undefined as unknown as T;

    const text = await res.text();
    const data = text ? safeJson(text) : null;

    if (!res.ok) {
        if (res.status === 401 && !options.suppressAuthCleared) emitAuthCleared();
        const message = (data && (data.error || (data as { message?: string }).message)) || `HTTP ${res.status}`;
        throw new ApiError(message, res.status, data);
    }
    return data as T;
}

export interface RegisterRequest {
    email: string;
    username: string;
    verifier: string;
    saltClient: string;
    dekEncrypted: string;
    dekNonce: string;
}
export interface LoginRequest { email: string; verifier: string; }
export interface LoginResponse { user: PublicUser; }
export interface SaltResponse { email: string; saltClient: string; }

export interface VaultItem {
    id?: string;
    userId?: string;
    titleCipher: string;   titleNonce: string;
    usernameCipher: string; usernameNonce: string;
    passwordCipher: string; passwordNonce: string;
    url?: string;
    notesCipher?: string;  notesNonce?: string;
    createdAt?: string;    updatedAt?: string;
}

export type CreateCredentialRequest = {
    title: string;
    usernameCipher: string;
    usernameNonce: string;
    passwordCipher: string;
    passwordNonce: string;
    url?: string;
    notes?: string;
};

export type UpdateCredentialRequest = {
    service?: string;
    websiteLink?: string;
    usernameEncrypted?: string;
    usernameNonce?: string;
    passwordEncrypted?: string;
    passwordNonce?: string;
};

export type PublicCredential = {
    credentialId: string;
    service: string;
    websiteLink: string;
    usernameEncrypted: string;
    usernameNonce: string;
    passwordEncrypted: string;
    passwordNonce: string;
};

export type GetAllCredentialResponse = {
    credentials: PublicCredential[];
};

export const api = {
    health: () => req<{ ok: boolean }>(`/health`),

    getSalt: (identifier: string) =>
        req<SaltResponse>(`/auth/salt?identifier=${encodeURIComponent(identifier)}`),
    register: (body: RegisterRequest) =>
        req<{ id: string }>(`/auth/register`, { method: 'POST', body: JSON.stringify(body) }),
    login: (body: LoginRequest) =>
        req<LoginResponse>(`/auth/login`, { method: 'POST', body: JSON.stringify(body) }),
    logout: () => req<void>(`/auth/logout`, { method: 'POST' }),
    currentUser: () => req<PublicUser>(`/auth/me`, {}, { suppressAuthCleared: true }),

    listVault: () => req<VaultItem[]>(`/vault`),
    createVault: (body: Partial<VaultItem>) =>
        req<VaultItem>(`/vault`, { method: 'POST', body: JSON.stringify(body) }),
    updateVault: (id: string, body: Partial<VaultItem>) =>
        req<VaultItem>(`/vault/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    deleteVault: (id: string) =>
        req<{ ok: boolean }>(`/vault/${id}`, { method: 'DELETE' }),

    createCredential: (body: CreateCredentialRequest) =>
        req<PublicCredential>(`/credential`, { method: 'POST', body: JSON.stringify(body) }),

    updateCredential: (id: string, body: UpdateCredentialRequest) =>
        req<PublicCredential>(`/credential/${id}`, { method: 'PUT', body: JSON.stringify(body) }),
    deleteCredential: (id: string) =>
        req<void>(`/credential/${id}`, { method: 'DELETE' }),

    fetchCredentials: () => req<GetAllCredentialResponse>(`/credentials`),
};
