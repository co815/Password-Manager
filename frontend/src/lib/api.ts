const API_ORIGIN = import.meta.env.VITE_API_ORIGIN ?? 'http://localhost:8080';

function safeJson(s: string) { try { return JSON.parse(s); } catch { return null; } }

async function req<T>(path: string, init: RequestInit = {}): Promise<T> {
    const res = await fetch(`${API_ORIGIN}/api${path}`, {
        ...init,
        headers: {
            'Content-Type': 'application/json',
            ...(init.headers || {}),
        },
        credentials: 'include',
    });

    if (res.status === 204) return undefined as unknown as T;

    const text = await res.text();
    const data = text ? safeJson(text) : null;

    if (!res.ok) {
        const message = (data && (data.error || data.message)) || `HTTP ${res.status}`;
        const err: any = new Error(message);
        err.status = res.status;
        err.data = data;
        throw err;
    }
    return data as T;
}

export interface PublicUser {
    id: string;
    email: string;
    saltClient: string;
    dekEncrypted: string;
    dekNonce: string;
}

export interface RegisterRequest {
    email: string;
    verifier: string;
    saltClient: string;
    dekEncrypted: string;
    dekNonce: string;
}

export interface LoginRequest {
    email: string;
    verifier: string;
}

export interface LoginResponse {
    accessToken: string;
    user: PublicUser;
}

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

export const api = {
    getSalt: (email: string) =>
        req<{ saltClient: string }>(`/auth/salt?email=${encodeURIComponent(email)}`),

    register: (body: RegisterRequest) =>
        req<{ id: string }>(`/auth/register`, { method: 'POST', body: JSON.stringify(body) }),

    login: (body: LoginRequest) =>
        req<LoginResponse>(`/auth/login`, { method: 'POST', body: JSON.stringify(body) }),

    listVault: (token: string) =>
        req<VaultItem[]>(`/vault`, { headers: { Authorization: `Bearer ${token}` } }),

    createVault: (token: string, body: Partial<VaultItem>) =>
        req<VaultItem>(`/vault`, {
            method: 'POST',
            body: JSON.stringify(body),
            headers: { Authorization: `Bearer ${token}` },
        }),

    updateVault: (token: string, id: string, body: Partial<VaultItem>) =>
        req<VaultItem>(`/vault/${id}`, {
            method: 'PUT',
            body: JSON.stringify(body),
            headers: { Authorization: `Bearer ${token}` },
        }),

    deleteVault: (token: string, id: string) =>
        req<{ ok: boolean }>(`/vault/${id}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${token}` },
        }),
};
