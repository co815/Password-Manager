import { createContext, useContext, useMemo, useState } from 'react';
import type { PropsWithChildren } from 'react';

export type AuthUser = { id: string; email: string; [k: string]: any } | null;

type AuthCtx = {
    token: string | null;
    user: AuthUser;
    login: (token: string, user: any) => void;
    logout: () => void;
};

const Ctx = createContext<AuthCtx>({
    token: null,
    user: null,
    login: () => {},
    logout: () => {},
});

export const useAuth = () => useContext(Ctx);

export default function AuthProvider({ children }: PropsWithChildren) {
    const [token, setToken] = useState<string | null>(() => localStorage.getItem('token'));
    const [user, setUser] = useState<AuthUser>(() => {
        const raw = localStorage.getItem('profile');
        return raw ? JSON.parse(raw) : null;
    });

    const login = (t: string, u: any) => {
        setToken(t);
        setUser(u);
        localStorage.setItem('token', t);
        localStorage.setItem('profile', JSON.stringify(u));
    };

    const logout = () => {
        setToken(null);
        setUser(null);
        localStorage.removeItem('token');
        localStorage.removeItem('profile');
        sessionStorage.removeItem('pm-had-dek');
        window.location.href = '/';
    };

    const value = useMemo(() => ({ token, user, login, logout }), [token, user]);
    return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
