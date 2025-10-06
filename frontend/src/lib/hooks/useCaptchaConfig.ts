import {useEffect, useState} from 'react';

import {api, type CaptchaConfigResponse} from '../api';

const DEFAULT_CONFIG: CaptchaConfigResponse = {enabled: false, provider: 'NONE', siteKey: null};

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
        inflight = api.getCaptchaConfig()
            .catch((err) => {
                if (import.meta.env.DEV) {
                    console.warn('Failed to load CAPTCHA configuration, falling back to defaults.', err);
                }
                return DEFAULT_CONFIG;
            })
            .then((config) => {
                cachedConfig = config;
                return config;
            })
            .finally(() => {
                inflight = null;
            });
    }
    return inflight!;
}

export function resetCachedCaptchaConfig() {
    cachedConfig = null;
}

export default function useCaptchaConfig() {
    const [config, setConfig] = useState<CaptchaConfigResponse | null>(cachedConfig);
    const [loading, setLoading] = useState(!cachedConfig);
    const [error, setError] = useState<unknown>(null);

    useEffect(() => {
        if (config) {
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
                }
            })
            .catch((err) => {
                if (!cancelled) {
                    setConfig(DEFAULT_CONFIG);
                    setError(null);
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
    }, [config]);

    const refresh = () => {
        resetCachedCaptchaConfig();
        return loadCaptchaConfig()
            .then((data) => {
                setConfig(data);
                setError(null);
                return data;
            })
            .catch((err) => {
                setConfig(DEFAULT_CONFIG);
                setError(null);
                if (import.meta.env.DEV) {
                    console.warn('Failed to refresh CAPTCHA configuration, falling back to defaults.', err);
                }
                return DEFAULT_CONFIG;
            });
    };

    return {config, loading, error, refresh};
}