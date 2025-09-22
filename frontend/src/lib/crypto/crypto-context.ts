import { createContext, useContext } from 'react';

export type CryptoContextValue = {
    dek: CryptoKey | null;
    locked: boolean;
    hadDek: boolean;
    setDEK: (k: CryptoKey | null) => void;
    lockNow: () => void;
    disarm: () => void;
};

export const DEFAULT_IDLE_MS = Number(import.meta.env.VITE_IDLE_MS ?? 10 * 60 * 1000);
export const HAD_DEK_FLAG = 'pm-had-dek';

export const CryptoContext = createContext<CryptoContextValue>({
    dek: null,
    locked: true,
    hadDek: false,
    setDEK: () => {},
    lockNow: () => {},
    disarm: () => {},
});

export const useCrypto = () => useContext(CryptoContext);