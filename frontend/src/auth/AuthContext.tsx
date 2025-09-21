import { createContext, useContext, useEffect, useMemo, useState, useCallback } from 'react';
import type { PropsWithChildren } from 'react';
import { AUTH_CLEARED_EVENT, clearAuth, getProfile } from '../lib/api';
import type { PublicUser } from '../lib/api';
export type AuthUser = PublicUser | null;

type AuthCtx = {
    token: string | null;
    user: AuthUser;
    login: (token: string, user: PublicUser) => void;
    logout: () => void;
};

const Ctx = createContext<AuthCtx>({
    token: null,
    user: null,
    login: (_token: string, _user: PublicUser) => {},
    logout: () => {},
});

export const useAuth = () => useContext(Ctx);

export default function AuthProvider({ children }: PropsWithChildren) {
    const [token, setToken] = useState<string | null>(() => localStorage.getItem('token'));
    const [user, setUser] = useState<AuthUser>(() => getProfile());

    const applyAuthCleared = useCallback(() => {
        setToken(null);
        setUser(null);
        sessionStorage.removeItem('pm-had-dek');
    }, []);

    useEffect(() => {
        const onAuthCleared = (_event: Event) => {
            applyAuthCleared();
        };

        const onStorage = (event: StorageEvent) => {
            if (event.storageArea !== localStorage) return;
            if (event.key === null || event.key === 'token' || event.key === 'profile') {
                const hasToken = localStorage.getItem('token');
                if (!hasToken) {
                    applyAuthCleared();
                }
            }
        };

        window.addEventListener(AUTH_CLEARED_EVENT, onAuthCleared);
        window.addEventListener('storage', onStorage);
        return () => {
            window.removeEventListener(AUTH_CLEARED_EVENT, onAuthCleared);
            window.removeEventListener('storage', onStorage);
        };
    }, [applyAuthCleared]);

    const login = (t: string, u: PublicUser) => {
        setToken(t);
        setUser(u);
        localStorage.setItem('token', t);
        localStorage.setItem('profile', JSON.stringify(u));
    };

    const logout = () => {
        clearAuth();
        applyAuthCleared();
        window.location.href = '/';
    };

    const value = useMemo(() => ({ token, user, login, logout }), [token, user]);
    return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
