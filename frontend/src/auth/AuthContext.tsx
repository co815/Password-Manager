import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { PropsWithChildren } from 'react';
import { AUTH_CLEARED_EVENT, api } from '../lib/api';
import type { PublicUser } from '../lib/api';
import { AuthContext, type AuthContextValue, type AuthUser } from './auth-context';

export default function AuthProvider({children}: PropsWithChildren) {
    const [user, setUser] = useState<AuthUser>(null);
    const [loading, setLoading] = useState(true);
    const refreshEpochRef = useRef(0);

    const applyAuthCleared = useCallback(() => {
        refreshEpochRef.current += 1;
        setUser(null);
        setLoading(false);
        sessionStorage.removeItem('pm-had-dek');
    }, []);

    const refresh = useCallback(async () => {
        const token = ++refreshEpochRef.current;
        const isLatest = () => refreshEpochRef.current === token;

        if (isLatest()) {
            setLoading(true);
        }
        try {
            const profile = await api.currentUser();
            if (isLatest()) {
                setUser(profile);
            }
        } catch {
            if (isLatest()) {
                setUser(null);
            }
        } finally {
            if (isLatest()) {
                setLoading(false);
            }
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
        refreshEpochRef.current += 1;
        setUser(u);
        setLoading(false);
    }, []);

    const logout = useCallback(async () => {
        try {
            await api.logout();
        } catch (error) {
            if (import.meta.env.DEV) {
                console.error('Failed to logout user', error);
            }
        } finally {
            applyAuthCleared();
            window.location.href = '/';
        }
    }, [applyAuthCleared]);

    const value = useMemo<AuthContextValue>(
        () => ({user, loading, login, logout, refresh}),
        [user, loading, login, logout, refresh],
    );

    return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
