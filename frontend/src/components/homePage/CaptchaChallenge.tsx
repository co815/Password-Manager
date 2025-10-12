import {forwardRef, useEffect, useImperativeHandle, useMemo, useRef, type CSSProperties} from 'react';

import type {CaptchaProvider} from '../../lib/api';

export interface CaptchaHandle {
    reset(): void;
}

interface CaptchaChallengeProps {
    provider: CaptchaProvider;
    siteKey: string;
    theme?: 'light' | 'dark';
    onChange: (token: string | null) => void;
    onExpired: () => void;
    onErrored: (message?: string) => void;
}

type CaptchaWindow = Window & {
    grecaptcha?: {
        ready?(cb: () => void): void;
        render(container: HTMLElement, parameters: Record<string, unknown>): number;
        reset(id?: number): void;
        remove?(id?: number): void;
    };
    hcaptcha?: {
        render(container: HTMLElement, parameters: Record<string, unknown>): string | number;
        reset(id?: string | number): void;
        remove?(id?: string | number): void;
    };
};

const RECAPTCHA_SRC = 'https://www.google.com/recaptcha/api.js?render=explicit';
const HCAPTCHA_SRC = 'https://hcaptcha.com/1/api.js?render=explicit';

const scriptPromises = new Map<string, Promise<void>>();

function getExistingScript(src: string): HTMLScriptElement | null {
    if (typeof document === 'undefined') {
        return null;
    }
    return (
        document.querySelector<HTMLScriptElement>(`script[data-captcha-src="${src}"]`)
        ?? document.querySelector<HTMLScriptElement>(`script[src="${src}"]`)
    );
}

function ensureScript(src: string, globalName: 'grecaptcha' | 'hcaptcha'): Promise<void> {
    if (typeof window === 'undefined') {
        return Promise.reject(new Error('Window object is not available.'));
    }

    const typedWindow = window as CaptchaWindow;
    if (globalName === 'grecaptcha' && typedWindow.grecaptcha) {
        return Promise.resolve();
    }
    if (globalName === 'hcaptcha' && typedWindow.hcaptcha) {
        return Promise.resolve();
    }

    if (scriptPromises.has(src)) {
        return scriptPromises.get(src)!;
    }

    const existing = getExistingScript(src);
    if (existing?.dataset.captchaLoaded === 'true') {
        return Promise.resolve();
    }

    const promise = new Promise<void>((resolve, reject) => {
        const script = existing ?? document.createElement('script');
        const cleanup = () => {
            script.removeEventListener('load', handleLoad);
            script.removeEventListener('error', handleError);
        };
        const handleLoad = () => {
            cleanup();
            script.dataset.captchaLoaded = 'true';
            resolve();
        };
        const handleError = () => {
            cleanup();
            delete script.dataset.captchaLoaded;
            scriptPromises.delete(src);
            if (script.parentNode) {
                script.parentNode.removeChild(script);
            }
            reject(new Error(`Failed to load script: ${src}`));
        };

        script.addEventListener('load', handleLoad);
        script.addEventListener('error', handleError);

        if (!existing) {
            script.async = true;
            script.defer = true;
            script.src = src;
            script.dataset.captchaLoaded = 'false';
            script.setAttribute('data-captcha-src', src);
            document.head.appendChild(script);
        } else {
            script.async = true;
            script.defer = true;
            script.setAttribute('data-captcha-src', src);
            if (script.dataset.captchaLoaded !== 'true') {
                script.dataset.captchaLoaded = 'false';
            }
            if (script.src !== src) {
                script.src = src;
            } else if (script.dataset.captchaLoaded === 'false') {
                // Retry the download by forcing a new request.
                script.src = '';
                script.src = src;
            }
    });

    scriptPromises.set(src, promise);
    return promise;
}

function useLatest<T>(value: T) {
    const ref = useRef(value);
    ref.current = value;
    return ref;
}


const WRAPPER_STYLE: CSSProperties = {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    width: '100%',
};

const CaptchaChallenge = forwardRef<CaptchaHandle, CaptchaChallengeProps>(
    ({provider, siteKey, theme, onChange, onExpired, onErrored}, ref) => {
        const containerRef = useRef<HTMLDivElement | null>(null);
        const widgetIdRef = useRef<number | string | null>(null);
        const activeProviderRef = useRef<CaptchaProvider>('NONE');

        const onChangeRef = useLatest(onChange);
        const onExpiredRef = useLatest(onExpired);
        const onErroredRef = useLatest(onErrored);

        useImperativeHandle(ref, () => ({
            reset() {
                if (typeof window === 'undefined') {
                    return;
                }
                const typedWindow = window as CaptchaWindow;
                if (activeProviderRef.current === 'RECAPTCHA' && widgetIdRef.current != null) {
                    typedWindow.grecaptcha?.reset(widgetIdRef.current as number);
                } else if (activeProviderRef.current === 'HCAPTCHA' && widgetIdRef.current != null) {
                    typedWindow.hcaptcha?.reset(widgetIdRef.current);
                }
            },
        }), []);

        useEffect(() => {
            if (typeof window === 'undefined') {
                return undefined;
            }

            widgetIdRef.current = null;
            activeProviderRef.current = 'NONE';

            if (!siteKey || provider === 'NONE') {
                if (containerRef.current) {
                    containerRef.current.innerHTML = '';
                }
                return undefined;
            }

            let cancelled = false;

            const loadAndRender = async () => {
                try {
                    if (provider === 'RECAPTCHA') {
                        await ensureScript(RECAPTCHA_SRC, 'grecaptcha');
                        if (cancelled) return;

                        const typedWindow = window as CaptchaWindow;
                        const api = typedWindow.grecaptcha;
                        if (!api || typeof api.render !== 'function') {
                            throw new Error('reCAPTCHA could not be initialized.');
                        }

                        const renderWidget = () => {
                            if (cancelled || !containerRef.current) return;
                            containerRef.current.innerHTML = '';
                            widgetIdRef.current = api.render(containerRef.current, {
                                sitekey: siteKey,
                                theme,
                                callback: (token: string) => {
                                    onChangeRef.current(token ?? null);
                                },
                                'expired-callback': () => {
                                    onExpiredRef.current();
                                    onChangeRef.current(null);
                                },
                                'error-callback': () => {
                                    onErroredRef.current();
                                    onChangeRef.current(null);
                                },
                            });
                            activeProviderRef.current = 'RECAPTCHA';
                        };

                        if (typeof api.ready === 'function') {
                            api.ready(renderWidget);
                        } else {
                            renderWidget();
                        }
                    } else if (provider === 'HCAPTCHA') {
                        await ensureScript(HCAPTCHA_SRC, 'hcaptcha');
                        if (cancelled) return;

                        const typedWindow = window as CaptchaWindow;
                        const api = typedWindow.hcaptcha;
                        if (!api || typeof api.render !== 'function') {
                            throw new Error('hCaptcha could not be initialized.');
                        }

                        if (!containerRef.current) {
                            return;
                        }

                        containerRef.current.innerHTML = '';
                        widgetIdRef.current = api.render(containerRef.current, {
                            sitekey: siteKey,
                            theme,
                            callback: (token: string | null) => {
                                onChangeRef.current(token ?? null);
                            },
                            'expired-callback': () => {
                                onExpiredRef.current();
                                onChangeRef.current(null);
                            },
                            'error-callback': (error?: string) => {
                                onErroredRef.current(error);
                                onChangeRef.current(null);
                            },
                            'close-callback': () => {
                                onExpiredRef.current();
                                onChangeRef.current(null);
                            },
                        });
                        activeProviderRef.current = 'HCAPTCHA';
                    }
                } catch (error) {
                    if (cancelled) {
                        return;
                    }
                    const message = error instanceof Error ? error.message : undefined;
                    onErroredRef.current(message);
                }
            };

            loadAndRender().catch((error) => {
                if (cancelled) {
                    return;
                }
                const message = error instanceof Error ? error.message : undefined;
                onErroredRef.current(message);
            });

            return () => {
                cancelled = true;
                if (typeof window === 'undefined') {
                    return;
                }
                const typedWindow = window as CaptchaWindow;
                if (activeProviderRef.current === 'RECAPTCHA' && widgetIdRef.current != null) {
                    typedWindow.grecaptcha?.reset(widgetIdRef.current as number);
                    typedWindow.grecaptcha?.remove?.(widgetIdRef.current as number);
                } else if (activeProviderRef.current === 'HCAPTCHA' && widgetIdRef.current != null) {
                    typedWindow.hcaptcha?.reset(widgetIdRef.current);
                    typedWindow.hcaptcha?.remove?.(widgetIdRef.current);
                }
                widgetIdRef.current = null;
                activeProviderRef.current = 'NONE';
                if (containerRef.current) {
                    containerRef.current.innerHTML = '';
                }
            };
        }, [provider, siteKey, theme]);

        const minHeight = useMemo(() => {
            if (provider === 'RECAPTCHA') {
                return 78;
            }
            if (provider === 'HCAPTCHA') {
                return 82;
            }
            return undefined;
        }, [provider]);

        if (!siteKey || provider === 'NONE') {
            return null;
        }

        return <div ref={containerRef} style={{...WRAPPER_STYLE, minHeight}}/>;
    },
);

CaptchaChallenge.displayName = 'CaptchaChallenge';

export default CaptchaChallenge;