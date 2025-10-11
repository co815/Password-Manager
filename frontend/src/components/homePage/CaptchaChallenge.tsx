import {forwardRef, useEffect, useImperativeHandle, useRef} from 'react';

import type {CaptchaProvider} from '../../lib/api';

type RecaptchaWidgetId = number | null;
type HcaptchaWidgetId = string | null;

declare global {
    interface Window {
        grecaptcha?: {
            ready: (cb: () => void) => void;
            render: (
                container: HTMLElement,
                parameters: {
                    sitekey: string;
                    theme?: 'light' | 'dark';
                    callback: (token: string | null) => void;
                    'error-callback': () => void;
                    'expired-callback': () => void;
                },
            ) => number;
            reset: (widgetId?: number | null) => void;
        };
        hcaptcha?: {
            render: (
                container: HTMLElement,
                parameters: {
                    sitekey: string;
                    theme?: 'light' | 'dark';
                    callback: (token: string | null) => void;
                    'error-callback': (error?: string) => void;
                    'expired-callback': () => void;
                },
            ) => string;
            reset: (widgetId?: string | null) => void;
            remove?: (widgetId?: string | null) => void;
        };
    }
}

const RECAPTCHA_SCRIPT_SRC = 'https://www.google.com/recaptcha/api.js?render=explicit';
const HCAPTCHA_SCRIPT_SRC = 'https://js.hcaptcha.com/1/api.js?render=explicit';

const scriptPromises: Partial<Record<Exclude<CaptchaProvider, 'NONE'>, Promise<void>>> = {};

function ensureScript(provider: Exclude<CaptchaProvider, 'NONE'>): Promise<void> {
    if (typeof window === 'undefined' || typeof document === 'undefined') {
        return Promise.reject(new Error('CAPTCHA scripts require a browser environment.'));
    }

    if (provider === 'RECAPTCHA' && window.grecaptcha && typeof window.grecaptcha.render === 'function') {
        return Promise.resolve();
    }

    if (provider === 'HCAPTCHA' && window.hcaptcha && typeof window.hcaptcha.render === 'function') {
        return Promise.resolve();
    }

    if (!scriptPromises[provider]) {
        const src = provider === 'RECAPTCHA' ? RECAPTCHA_SCRIPT_SRC : HCAPTCHA_SCRIPT_SRC;
        const attribute = provider === 'RECAPTCHA' ? 'data-recaptcha-script' : 'data-hcaptcha-script';

        scriptPromises[provider] = new Promise<void>((resolve, reject) => {
            const existing = document.querySelector<HTMLScriptElement>(`script[${attribute}]`);
            if (existing) {
                if (existing.dataset.loaded === 'true') {
                    resolve();
                    return;
                }
                existing.addEventListener('load', () => {
                    existing.dataset.loaded = 'true';
                    resolve();
                }, {once: true});
                existing.addEventListener('error', () => {
                    reject(new Error(`Failed to load CAPTCHA script from ${src}`));
                }, {once: true});
                return;
            }

            const script = document.createElement('script');
            script.src = src;
            script.async = true;
            script.defer = true;
            script.setAttribute(attribute, 'true');
            script.addEventListener('load', () => {
                script.dataset.loaded = 'true';
                resolve();
            }, {once: true});
            script.addEventListener('error', () => {
                reject(new Error(`Failed to load CAPTCHA script from ${src}`));
            }, {once: true});
            document.head.appendChild(script);
        });
    }

    return scriptPromises[provider]!;
}

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

const CaptchaChallenge = forwardRef<CaptchaHandle, CaptchaChallengeProps>(
    ({provider, siteKey, theme, onChange, onExpired, onErrored}, ref) => {
        const containerRef = useRef<HTMLDivElement | null>(null);
        const recaptchaIdRef = useRef<RecaptchaWidgetId>(null);
        const hcaptchaIdRef = useRef<HcaptchaWidgetId>(null);

        useImperativeHandle(
            ref,
            () => ({
                reset() {
                    if (provider === 'RECAPTCHA') {
                        if (recaptchaIdRef.current !== null) {
                            window.grecaptcha?.reset(recaptchaIdRef.current);
                        }
                    } else if (provider === 'HCAPTCHA') {
                        if (hcaptchaIdRef.current !== null) {
                            window.hcaptcha?.reset(hcaptchaIdRef.current);
                        }
                    }
                },
            }),
            [provider],
        );

        useEffect(() => {
            if (!siteKey || provider === 'NONE') {
                return () => undefined;
            }
            if (!containerRef.current) {
                return () => undefined;
            }

            let cancelled = false;
            const container = containerRef.current;
            container.innerHTML = '';
            recaptchaIdRef.current = null;
            hcaptchaIdRef.current = null;

            ensureScript(provider)
                .then(() => {
                    if (cancelled) {
                        return;
                    }
                    if (!containerRef.current) {
                        return;
                    }

                    if (provider === 'RECAPTCHA') {
                        const recaptcha = window.grecaptcha;
                        if (!recaptcha || typeof recaptcha.render !== 'function') {
                            onErrored('reCAPTCHA is not available.');
                            return;
                        }

                        recaptcha.ready(() => {
                            if (cancelled || !containerRef.current) {
                                return;
                            }
                            try {
                                const widgetId = recaptcha.render(containerRef.current, {
                                    sitekey: siteKey,
                                    theme,
                                    callback: (token) => {
                                        onChange(token ?? null);
                                    },
                                    'error-callback': () => {
                                        onErrored();
                                    },
                                    'expired-callback': () => {
                                        onExpired();
                                    },
                                });
                                recaptchaIdRef.current = widgetId;
                            } catch (error) {
                                const message = error instanceof Error ? error.message : undefined;
                                onErrored(message ?? 'Unable to render the reCAPTCHA widget.');
                            }
                        });
                        return;
                    }
                    const hcaptcha = window.hcaptcha;
                    if (!hcaptcha || typeof hcaptcha.render !== 'function') {
                        onErrored('hCaptcha is not available.');
                        return;
                    }

                    try {
                        const widgetId = hcaptcha.render(containerRef.current, {
                            sitekey: siteKey,
                            theme,
                            callback: (token) => {
                                onChange(token ?? null);
                            },
                            'error-callback': (error) => {
                                onErrored(error);
                            },
                            'expired-callback': () => {
                                onExpired();
                            },
                        });
                        hcaptchaIdRef.current = widgetId;
                    } catch (error) {
                        const message = error instanceof Error ? error.message : undefined;
                        onErrored(message ?? 'Unable to render the hCaptcha widget.');
                    }
                })
                .catch((error) => {
                    const message = error instanceof Error ? error.message : undefined;
                    onErrored(message ?? 'Unable to load the CAPTCHA widget.');
                });

            return () => {
                cancelled = true;
                if (provider === 'RECAPTCHA' && recaptchaIdRef.current !== null) {
                    window.grecaptcha?.reset(recaptchaIdRef.current);
                }
                if (provider === 'HCAPTCHA' && hcaptchaIdRef.current !== null) {
                    if (window.hcaptcha?.remove) {
                        window.hcaptcha.remove(hcaptchaIdRef.current);
                    } else {
                        window.hcaptcha?.reset(hcaptchaIdRef.current);
                    }
                }
            };
        }, [provider, siteKey, theme, onChange, onErrored, onExpired]);

        if (!siteKey || provider === 'NONE') {
            return null;
        }

        return <div ref={containerRef}/>;
    },
);

CaptchaChallenge.displayName = 'CaptchaChallenge';

export default CaptchaChallenge;