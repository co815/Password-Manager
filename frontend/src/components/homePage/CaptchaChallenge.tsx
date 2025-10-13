import {forwardRef, useEffect, useImperativeHandle, useMemo, useRef, useState, type CSSProperties, type ChangeEvent} from 'react';
import {Box, TextField, Typography} from '@mui/material';

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
    hcaptcha?: {
        render(container: HTMLElement, parameters: Record<string, unknown>): string | number;
        reset(id?: string | number): void;
        remove?(id?: string | number): void;
    };
    turnstile?: {
        render(container: HTMLElement, parameters: Record<string, unknown>): string;
        reset(id?: string): void;
        remove?(id?: string): void;
    };
};

const RECAPTCHA_SRC = 'https://www.google.com/recaptcha/api.js?render=explicit';
const HCAPTCHA_SRC = 'https://hcaptcha.com/1/api.js?render=explicit';
const TURNSTILE_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
const DEFAULT_GENERIC_PROMPT = 'Type the word "human" to verify you are not a bot.';

const scriptPromises = new Map<string, Promise<void>>();

function waitForCaptchaApi<T>(
    getter: () => T | null | undefined,
    providerLabel: 'reCAPTCHA' | 'hCaptcha' | 'Turnstile',
    timeoutMs = 5000,
): Promise<T> {
    if (typeof window === 'undefined') {
        return Promise.reject(new Error('Window object is not available.'));
    }

    const start = Date.now();

    return new Promise<T>((resolve, reject) => {
        const check = () => {
            if (typeof window === 'undefined') {
                reject(new Error('Window object is not available.'));
                return;
            }

            try {
                const value = getter();
                if (value != null) {
                    resolve(value);
                    return;
                }
            } catch (error) {
                reject(error instanceof Error ? error : new Error(String(error)));
                return;
            }

            if (Date.now() - start >= timeoutMs) {
                reject(new Error(`${providerLabel} could not be initialized.`));
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

function ensureScript(src: string, globalName: 'grecaptcha' | 'hcaptcha' | 'turnstile'): Promise<void> {
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
    if (globalName === 'turnstile' && typedWindow.turnstile) {
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
            console.error('[CAPTCHA] Script failed to load:', src);
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
                script.src = '';
                script.src = src;
            }
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

interface GenericCaptchaProps {
    prompt: string;
    onChange: (token: string | null) => void;
    onExpired: () => void;
    onErrored: (message?: string) => void;
}

const GenericCaptcha = forwardRef<CaptchaHandle, GenericCaptchaProps>(
    ({prompt, onChange, onExpired, onErrored}, ref) => {
        const [value, setValue] = useState('');
        const [touched, setTouched] = useState(false);
        const wasFilledRef = useRef(false);

        useImperativeHandle(ref, () => ({
            reset() {
                setValue('');
                setTouched(false);
                wasFilledRef.current = false;
                onChange(null);
                onErrored(undefined);
            },
        }), [onChange, onErrored]);

        const trimmed = value.trim();
        const filled = trimmed.length > 0;

        useEffect(() => {
            onChange(filled ? trimmed : null);
            if (!filled && wasFilledRef.current) {
                onExpired();
            }
            wasFilledRef.current = filled;
        }, [filled, trimmed, onChange, onExpired]);

        useEffect(() => {
            if (!touched) {
                onErrored(undefined);
                return;
            }
            if (!filled) {
                onErrored('Please provide the requested answer.');
            } else {
                onErrored(undefined);
            }
        }, [filled, touched, onErrored]);

        const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
            setValue(event.target.value);
        };

        const handleBlur = () => {
            setTouched(true);
        };

        const showError = touched && !filled;

        return (
            <Box sx={{display: 'flex', flexDirection: 'column', gap: 1, width: '100%'}}>
                <Typography variant="body2" color="text.secondary">
                    {prompt || DEFAULT_GENERIC_PROMPT}
                </Typography>
                <TextField
                    fullWidth
                    value={value}
                    onChange={handleChange}
                    onBlur={handleBlur}
                    label="Human verification"
                    placeholder="Type the answer"
                    error={showError}
                    helperText={showError ? 'Please provide the requested answer.' : ' '}
                    autoComplete="off"
                />
            </Box>
        );
    }
);

const CaptchaChallenge = forwardRef<CaptchaHandle, CaptchaChallengeProps>(
    ({provider, siteKey, theme, onChange, onExpired, onErrored}, ref) => {
        if (provider === 'GENERIC') {
            return (
                <GenericCaptcha
                    ref={ref}
                    prompt={siteKey ?? DEFAULT_GENERIC_PROMPT}
                    onChange={onChange}
                    onExpired={onExpired}
                    onErrored={onErrored}
                />
            );
        }
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
                } else if (activeProviderRef.current === 'TURNSTILE' && widgetIdRef.current != null) {
                    typedWindow.turnstile?.reset(widgetIdRef.current as string);
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
                        const api = await waitForCaptchaApi(
                            () => {
                                const candidate = typedWindow.grecaptcha;
                                return candidate && typeof candidate.render === 'function'
                                    ? candidate
                                    : null;
                            },
                            'reCAPTCHA',
                        );

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
                        const api = await waitForCaptchaApi(
                            () => {
                                const candidate = typedWindow.hcaptcha;
                                return candidate && typeof candidate.render === 'function'
                                    ? candidate
                                    : null;
                            },
                            'hCaptcha',
                        );

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
                    } else if (provider === 'TURNSTILE') {
                        await ensureScript(TURNSTILE_SRC, 'turnstile');
                        if (cancelled) return;

                        const typedWindow = window as CaptchaWindow;
                        const api = await waitForCaptchaApi(
                            () => {
                                const candidate = typedWindow.turnstile;
                                return candidate && typeof candidate.render === 'function'
                                    ? candidate
                                    : null;
                            },
                            'Turnstile',
                        );

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
                            'error-callback': () => {
                                onErroredRef.current();
                                onChangeRef.current(null);
                            },
                            'timeout-callback': () => {
                                onExpiredRef.current();
                                onChangeRef.current(null);
                            },
                            'unsupported-callback': () => {
                                onErroredRef.current('CAPTCHA is not supported in this browser.');
                                onChangeRef.current(null);
                            },
                        });
                        activeProviderRef.current = 'TURNSTILE';
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
                if (message) {
                    console.error('[CAPTCHA] Unable to render widget:', message);
                } else {
                    console.error('[CAPTCHA] Unable to render widget due to an unknown error.');
                }
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
                } else if (activeProviderRef.current === 'TURNSTILE' && widgetIdRef.current != null) {
                    typedWindow.turnstile?.reset(widgetIdRef.current as string);
                    typedWindow.turnstile?.remove?.(widgetIdRef.current as string);
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
            if (provider === 'TURNSTILE') {
                return 65;
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