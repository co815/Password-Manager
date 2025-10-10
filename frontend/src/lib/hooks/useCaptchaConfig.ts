import {useCallback, useEffect, useState} from 'react';

import {api, type CaptchaConfigResponse, type CaptchaProvider} from '../api';

const DEFAULT_CONFIG: CaptchaConfigResponse = {enabled: false, provider: 'NONE', siteKey: null};

function normalizeCaptchaConfig(config: CaptchaConfigResponse | null | undefined): CaptchaConfigResponse {
    const rawProvider = typeof config?.provider === 'string' ? config.provider : 'NONE';
    const upper = rawProvider.toUpperCase();
    const provider: CaptchaProvider = upper === 'HCAPTCHA'
        ? 'HCAPTCHA'
        : upper === 'RECAPTCHA'
            ? 'RECAPTCHA'
            : 'NONE';
    const rawSiteKey = typeof config?.siteKey === 'string' ? config.siteKey.trim() : '';
    const siteKey = rawSiteKey ? rawSiteKey : null;
    const enabled = Boolean(config?.enabled && provider !== 'NONE' && siteKey);
    return {enabled, provider, siteKey};
}

let cachedConfig: CaptchaConfigResponse | null = null;
let inflight: Promise<CaptchaConfigResponse> | null = null;

async function loadCaptchaConfig(): Promise<CaptchaConfigResponse> {
    if (typeof fetch !== 'function') {
        cachedConfig = DEFAULT_CONFIG;
        return cachedConfig;
    }
    if (cachedConfig) {
        return cachedConfig;
    }
    if (!inflight) {
        inflight = api
            .getCaptchaConfig()
            .then((config) => {
                const normalized = normalizeCaptchaConfig(config);
                cachedConfig = normalized;
                return normalized;
            })
            .finally(() => {
                inflight = null;
            });
    }
    return inflight!;
}

export function resetCachedCaptchaConfig() {
    cachedConfig = null;
    inflight = null;
}

export default function useCaptchaConfig() {
    const [config, setConfig] = useState<CaptchaConfigResponse | null>(cachedConfig);
    const [loading, setLoading] = useState(!cachedConfig);
    const [error, setError] = useState<unknown>(null);
    const [retryCount, setRetryCount] = useState(0);

    useEffect(() => {
        if (cachedConfig) {
            setConfig(cachedConfig);
            setLoading(false);
            return;
        }

        let cancelled = false;
        setLoading(true);
        loadCaptchaConfig()
            .then((data) => {
                if (!cancelled) {
                    setConfig(data);
                    setError(null);
                    setRetryCount(0);
                }
            })
            .catch((err) => {
                if (!cancelled) {
                    setConfig(DEFAULT_CONFIG);
                    setError(err);
                    setRetryCount((count) => count + 1);
                    if (import.meta.env.DEV) {
                        console.warn('Failed to load CAPTCHA configuration, falling back to defaults.', err);
                    }
                }
            })
            .finally(() => {
                if (!cancelled) {
                    setLoading(false);
                }
            });

        return () => {
            cancelled = true;
        };
    }, []);

    const refresh = useCallback(() => {
        resetCachedCaptchaConfig();
        setLoading(true);
        return loadCaptchaConfig()
            .then((data) => {
                setConfig(data);
                setError(null);
                setRetryCount(0);
                return data;
            })
            .catch((err) => {
                setConfig(DEFAULT_CONFIG);
                setError(err);
                setRetryCount((count) => count + 1);
                if (import.meta.env.DEV) {
                    console.warn('Failed to refresh CAPTCHA configuration, falling back to defaults.', err);
                }
                return DEFAULT_CONFIG;
            })
            .finally(() => {
                setLoading(false);
            });
    }, []);

    useEffect(() => {
        if (!error) {
            return;
        }
        if (typeof window === 'undefined') {
            return;
        }
        if (loading) {
            return;
        }
        if (retryCount >= 3) {
            return;
        }

        const delay = Math.min(4000, 1000 * (retryCount + 1));
        const timer = window.setTimeout(() => {
            refresh().catch(() => undefined);
        }, delay);

        return () => {
            window.clearTimeout(timer);
        };
    }, [error, loading, refresh, retryCount]);

    return {config, loading, error, refresh};
}