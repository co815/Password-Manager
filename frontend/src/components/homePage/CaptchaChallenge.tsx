import {forwardRef, useEffect, useImperativeHandle, useMemo, useRef, type CSSProperties} from 'react';

import type {CaptchaProvider} from '../../lib/api';

/**
 * CAPTCHA integration checklist:
 *  - Register every domain that will host the app (include localhost/127.0.0.1) in the provider console.
 *  - Issue separate site/secret keys for development and production to avoid accidental abuse.
 *  - Update your Content-Security-Policy (script-src/connect-src) to allow the provider domains when enabling CAPTCHA.
 */

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
};

const RECAPTCHA_SRC = 'https://www.google.com/recaptcha/api.js?render=explicit';

const scriptPromises = new Map<string, Promise<void>>();

function waitForRecaptcha(timeoutMs = 5000): Promise<NonNullable<CaptchaWindow['grecaptcha']>> {
    if (typeof window === 'undefined') {
        return Promise.reject(new Error('Window object is not available.'));
    }

    const typedWindow = window as CaptchaWindow;
    if (typedWindow.grecaptcha) {
        return Promise.resolve(typedWindow.grecaptcha);
    }

    const start = Date.now();

    return new Promise((resolve, reject) => {
        const check = () => {
            if (typeof window === 'undefined') {
                reject(new Error('Window object is not available.'));
                return;
            }

            const api = (window as CaptchaWindow).grecaptcha;
            if (api) {
                resolve(api);
                return;
            }

            if (Date.now() - start >= timeoutMs) {
                reject(new Error('reCAPTCHA could not be initialized.'));
                return;
            }

            window.setTimeout(check, 50);
        };

        check();
    });
}

function getExistingScript(src: string): HTMLScriptElement | null {
    if (typeof document === 'undefined') {
        return null;
    }
    return (
        document.querySelector<HTMLScriptElement>(`script[data-captcha-src="${src}"]`)
        ?? document.querySelector<HTMLScriptElement>(`script[src="${src}"]`)
    );
}

function ensureRecaptchaScript(): Promise<void> {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
        return Promise.reject(new Error('Window object is not available.'));
    }

    const typedWindow = window as CaptchaWindow;
    if (typedWindow.grecaptcha) {
        return Promise.resolve();
    }

    if (scriptPromises.has(RECAPTCHA_SRC)) {
        return scriptPromises.get(RECAPTCHA_SRC)!;
    }

    const existing = getExistingScript(RECAPTCHA_SRC);
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
            scriptPromises.delete(RECAPTCHA_SRC);
            if (script.parentNode) {
                script.parentNode.removeChild(script);
            }
            console.error('[CAPTCHA] Script failed to load:', RECAPTCHA_SRC);
            reject(new Error(`Failed to load script: ${RECAPTCHA_SRC}`));
        };

        script.addEventListener('load', handleLoad);
        script.addEventListener('error', handleError);

        script.async = true;
        script.defer = true;
        script.src = RECAPTCHA_SRC;
        script.dataset.captchaLoaded = existing ? existing.dataset.captchaLoaded ?? 'false' : 'false';
        script.setAttribute('data-captcha-src', RECAPTCHA_SRC);

        if (!existing) {
            document.head.appendChild(script);
        } else if (script.dataset.captchaLoaded !== 'false') {
            // Already loaded, nothing else to do.
        } else if (script.src === RECAPTCHA_SRC) {
            script.src = '';
            script.src = RECAPTCHA_SRC;
        }
    });

    scriptPromises.set(RECAPTCHA_SRC, promise);
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
    ({provider, siteKey, theme = 'light', onChange, onExpired, onErrored}, ref) => {
        const containerRef = useRef<HTMLDivElement | null>(null);
        const widgetIdRef = useRef<number | null>(null);
        const activeProviderRef = useRef<CaptchaProvider>('NONE');

        const onChangeRef = useLatest(onChange);
        const onExpiredRef = useLatest(onExpired);
        const onErroredRef = useLatest(onErrored);

        useImperativeHandle(ref, () => ({
            reset() {
                if (typeof window === 'undefined') {
                    return;
                }
                if (activeProviderRef.current === 'RECAPTCHA' && widgetIdRef.current != null) {
                    (window as CaptchaWindow).grecaptcha?.reset(widgetIdRef.current);
                }
            },
        }), []);

        useEffect(() => {
            if (typeof window === 'undefined') {
                return undefined;
            }

            widgetIdRef.current = null;
            activeProviderRef.current = 'NONE';

            if (!siteKey || provider !== 'RECAPTCHA') {
                if (containerRef.current) {
                    containerRef.current.innerHTML = '';
                }
                return undefined;
            }

            let cancelled = false;

            const loadAndRender = async () => {
                try {
                    await ensureRecaptchaScript();
                    if (cancelled) return;

                    const api = await waitForRecaptcha();
                    if (cancelled) return;

                    const renderWidget = () => {
                        if (cancelled || !containerRef.current) {
                            return;
                        }
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
                } catch (error) {
                    const message = error instanceof Error ? error.message : undefined;
                    onErroredRef.current(message);
                    if (message) {
                        console.error('[CAPTCHA] Unable to render widget:', message);
                    } else {
                        console.error('[CAPTCHA] Unable to render widget due to an unknown error.');
                    }
                }
            };

            loadAndRender().catch(() => {
                // error already handled in loadAndRender
            });

            return () => {
                cancelled = true;
                if (typeof window === 'undefined') {
                    return;
                }
                if (activeProviderRef.current === 'RECAPTCHA' && widgetIdRef.current != null) {
                    const api = (window as CaptchaWindow).grecaptcha;
                    api?.reset(widgetIdRef.current);
                    api?.remove?.(widgetIdRef.current);
                }
                widgetIdRef.current = null;
                activeProviderRef.current = 'NONE';
                if (containerRef.current) {
                    containerRef.current.innerHTML = '';
                }
            };
        }, [provider, siteKey, theme, onChangeRef, onExpiredRef, onErroredRef]);

        const minHeight = useMemo(() => (provider === 'RECAPTCHA' ? 78 : undefined), [provider]);

        if (!siteKey || provider !== 'RECAPTCHA') {
            return null;
        }

        return <div ref={containerRef} style={{...WRAPPER_STYLE, minHeight}}/>;
    },
);

CaptchaChallenge.displayName = 'CaptchaChallenge';

export default CaptchaChallenge;
