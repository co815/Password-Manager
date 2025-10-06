import {forwardRef, useImperativeHandle, useRef} from 'react';

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
        const recaptchaRef = useRef<ReCAPTCHA | null>(null);
        const hcaptchaRef = useRef<HCaptcha | null>(null);

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
                    onChange={(token) => onChange(token)}
                    onExpired={onExpired}
                    onErrored={() => onErrored()}
                />
            );
        }

        if (provider === 'HCAPTCHA') {
            return (
                <HCaptcha
                    ref={hcaptchaRef}
                    sitekey={siteKey}
                    theme={theme}
                    onVerify={(token) => onChange(token)}
                    onExpire={onExpired}
                    onError={(event) => onErrored(typeof event === 'string' ? event : undefined)}
                />
            );
        }

        return null;
    },
);

CaptchaChallenge.displayName = 'CaptchaChallenge';

export default CaptchaChallenge;