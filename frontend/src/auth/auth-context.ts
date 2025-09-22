import { createContext, useContext } from 'react';
import type { PublicUser } from '../lib/api';

export type AuthUser = PublicUser | null;

export type AuthContextValue = {
    user: AuthUser;
    loading: boolean;
    login: (user: PublicUser) => void;
    logout: () => Promise<void>;
    refresh: () => Promise<void>;
};

export const AuthContext = createContext<AuthContextValue>({
    user: null,
    loading: true,
    login: () => {
        throw new Error('AuthContext login called outside of provider');
    },
    logout: () => Promise.resolve(),
    refresh: () => Promise.resolve(),
});

export const useAuth = () => useContext(AuthContext);