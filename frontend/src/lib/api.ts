const RAW_API_ORIGIN = import.meta.env.VITE_API_ORIGIN;
const API_BASE = RAW_API_ORIGIN
    ? `${RAW_API_ORIGIN.replace(/\/$/, '')}/api`
    : '/api';
const CSRF_COOKIE = 'XSRF-TOKEN';
const CSRF_HEADER = 'X-XSRF-TOKEN';
const SAFE_HTTP_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);
const CSRF_FETCH_CREDENTIALS: RequestCredentials = RAW_API_ORIGIN ? 'include' : 'same-origin';
let lastCsrfToken: string | null = null;

function isLikelySameSite(): boolean {
    if (typeof window === 'undefined') return true;
    if (!RAW_API_ORIGIN) return true;
    try {
        const apiUrl = new URL(RAW_API_ORIGIN, window.location.href);
        return (
            apiUrl.protocol === window.location.protocol
            && apiUrl.hostname === window.location.hostname
        );
    } catch {
        return false;
    }
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

function getCookie(name: string): string | null {
    if (typeof document === 'undefined') return null;
    const match = document.cookie
        .split(';')
        .map((part) => part.trim())
        .find((part) => part.startsWith(`${name}=`));
    if (!match) return null;
    return decodeURIComponent(match.substring(name.length + 1));
}

function setCookie(name: string, value: string) {
    if (typeof document === 'undefined') return;
    const secure = typeof window !== 'undefined' && window.location.protocol === 'https:';
    const attributes = [`path=/`, `SameSite=Strict`];
    if (secure) {
        attributes.push('Secure');
    }
    document.cookie = `${name}=${encodeURIComponent(value)}; ${attributes.join('; ')}`;
}

function rememberCsrfToken(token: string) {
    lastCsrfToken = token;
    if (typeof document === 'undefined') return;
    const existing = getCookie(CSRF_COOKIE);
    if (existing === token) return;
    if (isLikelySameSite()) {
        setCookie(CSRF_COOKIE, token);
    }
}

async function fetchAndRememberCsrf(path: string): Promise<string | null> {
    const res = await fetch(`${API_BASE}${path}`, {credentials: CSRF_FETCH_CREDENTIALS});
    if (!res.ok) {
        return null;
    }

    const headerToken = res.headers.get(CSRF_HEADER);
    if (headerToken) {
        rememberCsrfToken(headerToken);
        return headerToken;
    }
    const cookieToken = getCookie(CSRF_COOKIE);
    if (cookieToken) {
        rememberCsrfToken(cookieToken);
        return cookieToken;
    }
    return null;
}

async function refreshCsrfToken(): Promise<string | null> {
    try {
        const csrfToken = await fetchAndRememberCsrf('/auth/csrf');
        if (csrfToken) {
            return csrfToken;
        }
        const healthToken = await fetchAndRememberCsrf('/health');
        if (healthToken) {
            return healthToken;
        }
    } catch {
        // Ignore network errors here; the main request will surface failures to the caller.
    }

    const cookieToken = getCookie(CSRF_COOKIE);
    if (cookieToken) {
        rememberCsrfToken(cookieToken);
        return cookieToken;
    }
    return lastCsrfToken;
}

export function primeCsrfToken(): Promise<string | null> {
    return refreshCsrfToken();
}

async function ensureCsrfToken(method: string, forceRefresh = false): Promise<string | null> {
    if (SAFE_HTTP_METHODS.has(method) || typeof document === 'undefined') {
        return null;
    }

    let token = forceRefresh ? null : getCookie(CSRF_COOKIE) ?? lastCsrfToken;
    if (!token) {
        token = await refreshCsrfToken();
    }

    if (!token) {
        throw new ApiError('Missing CSRF token', 0, null);
    }
    return token;
}


export interface PublicUser {
    id: string;
    email: string;
    username: string;
    saltClient: string;
    dekEncrypted: string;
    dekNonce: string;
    avatarData: string | null;
    mfaEnabled: boolean;
    masterPasswordLastRotated: string | null;
    mfaEnabledAt: string | null;
}

export const AUTH_CLEARED_EVENT = 'auth-cleared';

function emitAuthCleared() {
    if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent(AUTH_CLEARED_EVENT));
    }
}

function safeJson(s: string) {
    try {
        return JSON.parse(s);
    } catch {
        return null;
    }
}

function mergeHeaders(init: RequestInit, extras?: Record<string, string | null | undefined>): Headers {
    const h = new Headers(init.headers || {});
    if (!h.has('Content-Type')) h.set('Content-Type', 'application/json');
    if (extras) {
        Object.entries(extras).forEach(([key, value]) => {
            if (value) h.set(key, value);
        });
    }
    return h;
}

interface RequestOptions {
    suppressAuthCleared?: boolean;
    skipCsrf?: boolean;
}

async function req<T>(
    path: string,
    init: RequestInit = {},
    options: RequestOptions = {},
): Promise<T> {
    const method = (init.method ?? 'GET').toUpperCase();
    const performFetch = async (forceRefresh: boolean) => {
        const csrfToken = options.skipCsrf ? null : await ensureCsrfToken(method, forceRefresh);
        return fetch(`${API_BASE}${path}`, {
            ...init,
            method,
            headers: mergeHeaders(init, {[CSRF_HEADER]: csrfToken ?? undefined}),
            credentials: init.credentials ?? 'include',
        });
    };

    const rememberFromResponse = (res: Response) => {
        const headerToken = res.headers.get(CSRF_HEADER);
        if (headerToken) {
            rememberCsrfToken(headerToken);
        }
    };

    let res = await performFetch(false);
    rememberFromResponse(res);
    if (res.status === 403 && !options.skipCsrf) {
        await primeCsrfToken();
        res = await performFetch(true);
        rememberFromResponse(res);
    }

    if (res.status === 204) return undefined as unknown as T;

    const text = await res.text();
    const data = text ? safeJson(text) : null;

    if (!res.ok) {
        if (res.status === 401 && !options.suppressAuthCleared) emitAuthCleared();
        const errorData = (data || {}) as { error?: string | null; message?: string | null };
        const message =
            (errorData.message && errorData.message.trim())
            || (errorData.error && errorData.error.trim())
            || `HTTP ${res.status}`;
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
    avatarData?: string | null;
    captchaToken?: string | null;
}

export interface LoginRequest {
    email: string;
    verifier: string;
    mfaCode?: string | null;
    recoveryCode?: string | null;
    captchaToken?: string | null;
}

export interface LoginResponse {
    user: PublicUser;
}

export interface SaltResponse {
    email: string;
    saltClient: string;
}

export type CaptchaProvider = 'NONE' | 'RECAPTCHA';

export interface CaptchaConfigResponse {
    enabled: boolean;
    provider: CaptchaProvider;
    siteKey: string | null;
}

export interface SimpleMessageResponse {
    message: string;
}

export interface MfaStatusResponse {
    enabled: boolean;
    enabledAt: string | null;
    recoveryCodesRemaining: number;
}

export interface MfaEnrollmentResponse {
    secret: string;
    otpauthUrl: string;
    recoveryCodes: string[];
}

export interface MfaDisableRequest {
    code?: string | null;
    recoveryCode?: string | null;
}

export interface RotateMasterPasswordRequest {
    currentVerifier: string;
    newVerifier: string;
    newSaltClient: string;
    newDekEncrypted: string;
    newDekNonce: string;
    invalidateSessions: boolean;
}

export interface RotateMasterPasswordResponse {
    rotatedAt: string;
    sessionsInvalidated: boolean;
}

export interface ResetMasterPasswordRequest {
    email: string;
    recoveryCode: string;
    newVerifier: string;
    newSaltClient: string;
    newDekEncrypted: string;
    newDekNonce: string;
    disableMfa: boolean;
}

export interface RevokeSessionsResponse {
    tokenVersion: number;
}

export interface VaultItem {
    id?: string;
    userId?: string;
    titleCipher: string;
    titleNonce: string;
    usernameCipher: string;
    usernameNonce: string;
    passwordCipher: string;
    passwordNonce: string;
    url?: string;
    notesCipher?: string;
    notesNonce?: string;
    createdAt?: string;
    updatedAt?: string;
}

export type CreateCredentialRequest = {
    title: string;
    usernameCipher: string;
    usernameNonce: string;
    passwordCipher: string;
    passwordNonce: string;
    url?: string;
    notes?: string;
    favorite?: boolean;
};

export type UpdateCredentialRequest = {
    service?: string;
    websiteLink?: string;
    usernameEncrypted?: string;
    usernameNonce?: string;
    passwordEncrypted?: string;
    passwordNonce?: string;
    favorite?: boolean;
};

export type PublicCredential = {
    credentialId: string;
    service: string;
    websiteLink: string;
    usernameEncrypted: string;
    usernameNonce: string;
    passwordEncrypted: string;
    passwordNonce: string;
    favorite: boolean;
};

export type GetAllCredentialResponse = {
    credentials: PublicCredential[];
};

export type UpdateCredentialFavoriteRequest = {
    favorite: boolean;
};

export interface AuditLogActor {
    id: string;
    email: string | null;
    username: string | null;
}

export interface AuditLogEntry {
    id: string;
    createdDate: string | null;
    action: string;
    targetType: string;
    targetId: string | null;
    details: string | null;
    actor: AuditLogActor | null;
}

export interface AuditLogListResponse {
    logs: AuditLogEntry[];
}

export const api = {
    health: () => req<{ ok: boolean }>(`/health`),

    getSalt: (identifier: string) =>
        req<SaltResponse>(`/auth/salt?identifier=${encodeURIComponent(identifier)}`),
    register: (body: RegisterRequest) =>
        req<{ id: string }>(`/auth/register`, {method: 'POST', body: JSON.stringify(body)}),
    login: (body: LoginRequest) =>
        req<LoginResponse>(`/auth/login`, {method: 'POST', body: JSON.stringify(body)}),
    getCaptchaConfig: () => req<CaptchaConfigResponse>(
        `/auth/captcha/config`,
        {},
        {suppressAuthCleared: true},
    ),
    resendVerification: (email: string) =>
        req<SimpleMessageResponse>(`/auth/resend-verification`, {
            method: 'POST',
            body: JSON.stringify({email}),
        }),
    logout: () => req<void>(`/auth/logout`, {method: 'POST'}),
    currentUser: () => req<PublicUser>(`/auth/me`, {}, {suppressAuthCleared: true}),
    updateAvatar: (avatarData: string | null) =>
        req<PublicUser>(`/auth/profile/avatar`, {
            method: 'PUT',
            body: JSON.stringify({avatarData}),
        }),
    mfaStatus: () => req<MfaStatusResponse>(`/auth/mfa/status`),
    mfaEnroll: () => req<MfaEnrollmentResponse>(`/auth/mfa/enroll`, {method: 'POST'}),
    mfaActivate: (code: string) =>
        req<MfaStatusResponse>(`/auth/mfa/activate`, {
            method: 'POST',
            body: JSON.stringify({code}),
        }),
    mfaDisable: (body: MfaDisableRequest) =>
        req<MfaStatusResponse>(`/auth/mfa/disable`, {
            method: 'POST',
            body: JSON.stringify({
                code: body.code ?? null,
                recoveryCode: body.recoveryCode ?? null,
            }),
        }),
    rotateMasterPassword: (body: RotateMasterPasswordRequest) =>
        req<RotateMasterPasswordResponse>(`/auth/master/rotate`, {
            method: 'POST',
            body: JSON.stringify(body),
        }),
    resetMasterPassword: (body: ResetMasterPasswordRequest) =>
        req<{ message: string }>(`/auth/master/reset`, {
            method: 'POST',
            body: JSON.stringify(body),
        }),
    revokeSessions: () =>
        req<RevokeSessionsResponse>(`/auth/sessions/revoke`, {method: 'POST'}),
    listVault: () => req<VaultItem[]>(`/vault`),
    createVault: (body: Partial<VaultItem>) =>
        req<VaultItem>(`/vault`, {method: 'POST', body: JSON.stringify(body)}),
    updateVault: (id: string, body: Partial<VaultItem>) =>
        req<VaultItem>(`/vault/${id}`, {method: 'PUT', body: JSON.stringify(body)}),
    deleteVault: (id: string) =>
        req<{ ok: boolean }>(`/vault/${id}`, {method: 'DELETE'}),

    createCredential: (body: CreateCredentialRequest) =>
        req<PublicCredential>(`/credential`, {method: 'POST', body: JSON.stringify(body)}),

    updateCredential: (id: string, body: UpdateCredentialRequest) =>
        req<PublicCredential>(`/credential/${id}`, {method: 'PUT', body: JSON.stringify(body)}),
    deleteCredential: (id: string) =>
        req<void>(`/credential/${id}`, {method: 'DELETE'}),

    updateCredentialFavorite: (id: string, favorite: boolean) =>
        req<PublicCredential>(`/credential/${id}/favorite`, {
            method: 'PUT',
            body: JSON.stringify({favorite}),
        }),

    fetchCredentials: () => req<GetAllCredentialResponse>(`/credentials`),

    listAuditLogs: (limit = 100) =>
        req<AuditLogListResponse>(`/audit-logs?limit=${encodeURIComponent(limit)}`),
};
