import {useEffect, useState} from 'react';

import {api, type CaptchaConfigResponse} from '../api';

let cachedConfig: CaptchaConfigResponse | null = null;
let inflight: Promise<CaptchaConfigResponse> | null = null;

async function loadCaptchaConfig(): Promise<CaptchaConfigResponse> {
    if (typeof fetch !== 'function') {
        cachedConfig = {enabled: false, provider: 'NONE', siteKey: null};
        return cachedConfig;
    }
    if (cachedConfig) {
        return cachedConfig;
    }
    if (!inflight) {
        inflight = api.getCaptchaConfig()
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
                    setError(err);
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
                setError(err);
                throw err;
            });
    };

    return {config, loading, error, refresh};
}