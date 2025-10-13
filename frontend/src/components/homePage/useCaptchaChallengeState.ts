import {useCallback, useEffect, useRef, useState} from 'react';

import useCaptchaConfig from '../../lib/hooks/useCaptchaConfig';
import type {CaptchaHandle} from './CaptchaChallenge';

type CaptchaStateOptions = {
    boundValue?: string | null;
};

export function useCaptchaChallengeState(options: CaptchaStateOptions = {}) {
    const {boundValue = null} = options;
    const captchaRef = useRef<CaptchaHandle | null>(null);
    const missingKeyLoggedRef = useRef(false);
    const [captchaToken, setCaptchaToken] = useState<string | null>(null);
    const [captchaError, setCaptchaError] = useState<string | null>(null);
    const [boundTokenValue, setBoundTokenValue] = useState<string | null>(null);

    const {
        config: captchaConfig,
        loading: captchaLoading,
        error: captchaConfigError,
        refresh: reloadCaptchaConfig,
    } = useCaptchaConfig();

    const rawCaptchaProvider = captchaConfig?.provider ?? 'NONE';
    const hasSiteKey = Boolean(captchaConfig?.siteKey && captchaConfig.siteKey.trim());
    const captchaEnabled = Boolean(
        captchaConfig?.enabled
        && rawCaptchaProvider === 'RECAPTCHA'
        && hasSiteKey
    );

    const siteKey = captchaEnabled ? captchaConfig?.siteKey ?? '' : '';
    const captchaProvider = captchaEnabled ? rawCaptchaProvider : 'NONE';

    const resetCaptcha = useCallback(() => {
        captchaRef.current?.reset();
        setCaptchaToken(null);
        setCaptchaError(null);
        setBoundTokenValue(null);
    }, []);

    useEffect(() => {
        if (!captchaEnabled) {
            resetCaptcha();
        }
    }, [captchaEnabled, resetCaptcha]);

    useEffect(() => {
        if (!captchaConfig || captchaLoading) {
            return;
        }
        if (captchaConfig.provider === 'RECAPTCHA' && !hasSiteKey && !missingKeyLoggedRef.current) {
            missingKeyLoggedRef.current = true;
            console.error(
                '[CAPTCHA] Missing site key for provider %s. Check RECAPTCHA_SITE_KEY or backend configuration.',
                captchaConfig.provider,
            );
        }
    }, [captchaConfig, captchaLoading, hasSiteKey]);

    useEffect(() => {
        if (!captchaEnabled) {
            return;
        }
        if (!boundValue) {
            setBoundTokenValue(null);
            return;
        }
        if (!boundTokenValue) {
            setBoundTokenValue(boundValue);
            return;
        }
        if (boundTokenValue !== boundValue) {
            resetCaptcha();
            setBoundTokenValue(boundValue);
        }
    }, [boundTokenValue, boundValue, captchaEnabled, resetCaptcha]);

    const setTokenAndClearError = useCallback((token: string | null) => {
        setCaptchaToken(token);
        if (token) {
            setCaptchaError(null);
            if (boundValue) {
                setBoundTokenValue(boundValue);
            }
        }
    }, [boundValue]);

    return {
        captchaEnabled,
        captchaProvider,
        siteKey,
        captchaLoading,
        captchaConfigError,
        reloadCaptchaConfig,
        captchaRef,
        captchaToken,
        setCaptchaToken: setTokenAndClearError,
        captchaError,
        setCaptchaError,
        resetCaptcha,
    };
}

export type CaptchaChallengeState = ReturnType<typeof useCaptchaChallengeState>;