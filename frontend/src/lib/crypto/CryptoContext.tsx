import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AUTH_CLEARED_EVENT } from '../api';
import {
    CryptoContext,
    DEFAULT_IDLE_MS,
    HAD_DEK_FLAG,
    type CryptoContextValue,
} from './crypto-context';

export default function CryptoProvider({
                                           children,
                                       }: {
    children: React.ReactNode;
}) {
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
        timerRef.current = window.setTimeout(lockNow, idleMsRef.current);
    }, [clearTimer, lockNow]);

    const setDEK = useCallback(
        (k: CryptoKey | null) => {
            setDek(k);
            setLocked(!k);
            if (k) {
                if (!hadDek) {
                    setHadDek(true);
                    sessionStorage.setItem(HAD_DEK_FLAG, '1');
                }
                armTimer();
            } else {
                clearTimer();
            }
        },
        [armTimer, clearTimer, hadDek]
    );

    const disarm = useCallback(() => {
        setHadDek(false);
        sessionStorage.removeItem(HAD_DEK_FLAG);
    }, []);

    useEffect(() => {
        const onAuthCleared = () => {
            lockNow();
            disarm();
        };

        window.addEventListener(AUTH_CLEARED_EVENT, onAuthCleared);

        return () => {
            window.removeEventListener(AUTH_CLEARED_EVENT, onAuthCleared);
        };
    }, [disarm, lockNow]);

    useEffect(() => {
        if (!dek) return;

        const reset: EventListener = () => {
            armTimer();
        };
        const events: (keyof WindowEventMap)[] = [
            'mousemove',
            'mousedown',
            'keydown',
            'scroll',
            'touchstart',
            'pointerdown',
            'wheel',
            'click',
        ];
        events.forEach((eventName) =>
            window.addEventListener(eventName, reset, {
                passive: true,
            })
        );

        const onVisibilityChange = () => {
            if (!document.hidden) armTimer();
        };
        const onBlur = () => armTimer();
        document.addEventListener('visibilitychange', onVisibilityChange);
        window.addEventListener('blur', onBlur);

        armTimer();

        return () => {
            events.forEach((eventName) => window.removeEventListener(eventName, reset));
            document.removeEventListener('visibilitychange', onVisibilityChange);
            window.removeEventListener('blur', onBlur);
            clearTimer();
        };
    }, [dek, armTimer, clearTimer]);

    const value = useMemo<CryptoContextValue>(
        () => ({
            dek,
            locked,
            hadDek,
            setDEK,
            lockNow,
            disarm,
        }),
        [dek, locked, hadDek, setDEK, lockNow, disarm]
    );

    return <CryptoContext.Provider value={value}>{children}</CryptoContext.Provider>;
}
