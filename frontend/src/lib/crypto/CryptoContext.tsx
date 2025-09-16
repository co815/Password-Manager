import {
    createContext, useCallback, useContext, useEffect,
    useMemo, useRef, useState
} from 'react';

type Ctx = {
    dek: CryptoKey | null;
    locked: boolean;
    hadDek: boolean;
    setDEK: (k: CryptoKey | null) => void;
    lockNow: () => void;
    disarm: () => void;
};

const CryptoCtx = createContext<Ctx>({
    dek: null, locked: true, hadDek: false,
    setDEK: () => {}, lockNow: () => {}, disarm: () => {}
});
export const useCrypto = () => useContext(CryptoCtx);

const DEFAULT_IDLE_MS = Number(import.meta.env.VITE_IDLE_MS ?? 8 * 60 * 1000);
const HAD_DEK_FLAG = 'pm-had-dek';

export default function CryptoProvider({ children }: { children: React.ReactNode }) {
    const [dek, setDek] = useState<CryptoKey | null>(null);
    const [locked, setLocked] = useState(true);
    const [hadDek, setHadDek] = useState<boolean>(
        () => sessionStorage.getItem(HAD_DEK_FLAG) === '1'
    );

    const timerRef = useRef<number | null>(null);
    const idleMsRef = useRef<number>(DEFAULT_IDLE_MS);

    const clearTimer = useCallback(() => {
        if (timerRef.current !== null) {
            window.clearTimeout(timerRef.current);
            timerRef.current = null;
        }
    }, []);

    const lockNow = useCallback(() => {
        clearTimer();
        setDek(null);
        setLocked(true);
    }, [clearTimer]);

    const armTimer = useCallback(() => {
        clearTimer();
        if (!dek) return;
        timerRef.current = window.setTimeout(() => lockNow(), idleMsRef.current);
    }, [dek, lockNow, clearTimer]);

    const setDEK = useCallback((k: CryptoKey | null) => {
        setDek(k);
        setLocked(!k);
        if (k) {
            if (!hadDek) { setHadDek(true); sessionStorage.setItem(HAD_DEK_FLAG, '1'); }
            armTimer();
        } else {
            clearTimer();
        }
    }, [armTimer, clearTimer, hadDek]);

    const disarm = useCallback(() => {
        setHadDek(false);
        sessionStorage.removeItem(HAD_DEK_FLAG);
    }, []);

    useEffect(() => {
        if (!dek) return;

        const reset = () => armTimer();
        const events: (keyof WindowEventMap)[] = [
            'mousemove','mousedown','keydown','scroll','touchstart','pointerdown','wheel','click'
        ];
        events.forEach(e => window.addEventListener(e, reset, { passive: true } as AddEventListenerOptions));

        const onVis = () => {
            if (document.hidden) lockNow(); else armTimer();
        };
        document.addEventListener('visibilitychange', onVis);
        window.addEventListener('blur', onVis);

        armTimer();

        return () => {
            events.forEach(e => window.removeEventListener(e, reset as any));
            document.removeEventListener('visibilitychange', onVis);
            window.removeEventListener('blur', onVis);
            clearTimer();
        };
    }, [dek, armTimer, lockNow, clearTimer]);

    const value = useMemo(() => ({
        dek, locked, hadDek, setDEK, lockNow, disarm
    }), [dek, locked, hadDek, setDEK, lockNow, disarm]);

    return <CryptoCtx.Provider value={value}>{children}</CryptoCtx.Provider>;
}
