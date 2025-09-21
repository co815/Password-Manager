import {createContext, useContext, useEffect, useMemo, useState, useCallback} from 'react';
import type {PropsWithChildren} from 'react';
import {AUTH_CLEARED_EVENT, api} from '../lib/api';
import type {PublicUser} from '../lib/api';

export type AuthUser = PublicUser | null;

type AuthCtx = {
    user: AuthUser;
    loading: boolean;
    login: (user: PublicUser) => void;
    logout: () => Promise<void>;
    refresh: () => Promise<void>;
};

const Ctx = createContext<AuthCtx>({
    user: null,
    loading: true,
    login: (_user: PublicUser) => {
    },
    logout: async () => {
    },
    refresh: async () => {
    },
});

export const useAuth = () => useContext(Ctx);

export default function AuthProvider({children}: PropsWithChildren) {
    const [user, setUser] = useState<AuthUser>(null);
    const [loading, setLoading] = useState(true);

    const applyAuthCleared = useCallback(() => {
        setUser(null);
        setLoading(false);
        sessionStorage.removeItem('pm-had-dek');
    }, []);

    const refresh = useCallback(async () => {
        try {
            setLoading(true);
            const profile = await api.currentUser();
            setUser(profile);
        } catch {
            setUser(null);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        refresh();
    }, [refresh]);

    useEffect(() => {
        const onAuthCleared = () => {
            applyAuthCleared();
        };

        window.addEventListener(AUTH_CLEARED_EVENT, onAuthCleared);

        return () => {
            window.removeEventListener(AUTH_CLEARED_EVENT, onAuthCleared);
        };
    }, [applyAuthCleared]);

    const login = useCallback((u: PublicUser) => {
        setUser(u);
        setLoading(false);
    }, []);

    const logout = useCallback(async () => {
        try {
            await api.logout();
        } catch {
        } finally {
            applyAuthCleared();
            window.location.href = '/';
        }
    }, [applyAuthCleared]);

    const value = useMemo(
        () => ({user, loading, login, logout, refresh}),
        [user, loading, login, logout, refresh],
    );

    return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
