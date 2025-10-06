import {forwardRef, useCallback, useImperativeHandle, useRef} from 'react';

import type {CaptchaProvider} from '../../lib/api';
import ReCAPTCHA from 'react-google-recaptcha';
import HCaptcha from '@hcaptcha/react-hcaptcha';

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
        const recaptchaRef = useRef<InstanceType<typeof ReCAPTCHA> | null>(null);
        const hcaptchaRef = useRef<InstanceType<typeof HCaptcha> | null>(null);

        const handleRecaptchaChange = useCallback(
            (token: string | null) => {
                onChange(token);
            },
            [onChange],
        );

        const handleRecaptchaError = useCallback(() => {
            onErrored();
        }, [onErrored]);

        const handleRecaptchaExpired = useCallback(() => {
            onExpired();
        }, [onExpired]);

        const handleHcaptchaVerify = useCallback(
            (token: string) => {
                onChange(token);
            },
            [onChange],
        );

        const handleHcaptchaError = useCallback(
            (event?: string) => {
                onErrored(event);
            },
            [onErrored],
        );

        const handleHcaptchaExpired = useCallback(() => {
            onExpired();
        }, [onExpired]);

        useImperativeHandle(
            ref,
            () => ({
                reset() {
                    if (provider === 'RECAPTCHA') {
                        recaptchaRef.current?.reset();
                    } else if (provider === 'HCAPTCHA') {
                        hcaptchaRef.current?.resetCaptcha();
                    }
                },
            }),
            [provider],
        );

        if (!siteKey || provider === 'NONE') {
            return null;
        }

        if (provider === 'RECAPTCHA') {
            return (
                <ReCAPTCHA
                    ref={recaptchaRef}
                    sitekey={siteKey}
                    theme={theme}
                    onChange={handleRecaptchaChange}
                    onExpired={handleRecaptchaExpired}
                    onErrored={handleRecaptchaError}
                />
            );
        }

        if (provider === 'HCAPTCHA') {
            return (
                <HCaptcha
                    ref={hcaptchaRef}
                    sitekey={siteKey}
                    theme={theme}
                    onVerify={handleHcaptchaVerify}
                    onExpire={handleHcaptchaExpired}
                    onError={(event) => {
                        handleHcaptchaError(typeof event === 'string' ? event : undefined)
                    }}
                />
            );
        }

        return null;
    },
);

CaptchaChallenge.displayName = 'CaptchaChallenge';

export default CaptchaChallenge;