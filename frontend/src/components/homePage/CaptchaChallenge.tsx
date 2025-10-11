import {forwardRef, useImperativeHandle, useMemo, useRef, type CSSProperties} from 'react';
import HCaptcha, {type HCaptchaHandle} from '@hcaptcha/react-hcaptcha';
import ReCAPTCHA from 'react-google-recaptcha';

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

const WRAPPER_STYLE: CSSProperties = {
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    width: '100%',
};

const CaptchaChallenge = forwardRef<CaptchaHandle, CaptchaChallengeProps>(
    ({provider, siteKey, theme, onChange, onExpired, onErrored}, ref) => {
        const recaptchaRef = useRef<ReCAPTCHA | null>(null);
        const hcaptchaRef = useRef<HCaptchaHandle | null>(null);

        useImperativeHandle(
            ref,
            () => ({
                reset() {
                    if (provider === 'RECAPTCHA') {
                        recaptchaRef.current?.reset();
                        return;
                    }
                    if (provider === 'HCAPTCHA') {
                        hcaptchaRef.current?.resetCaptcha();
                    }
                },
            }),
            [provider],
        );

        const content = useMemo(() => {
            if (!siteKey || provider === 'NONE') {
                return null;
            }
            if (provider === 'RECAPTCHA') {
                return (
                    <ReCAPTCHA
                        ref={recaptchaRef}
                        sitekey={siteKey}
                        theme={theme}
                        onChange={(token) => {
                            onChange(token ?? null);
                            if (!token) {
                                onExpired();
                            }
                        }}
                        onExpired={() => {
                            onExpired();
                            onChange(null);
                        }}
                        onErrored={() => {
                            onErrored();
                            onChange(null);
                        }}
                    />
                );
            }


            return (
                <HCaptcha
                    ref={hcaptchaRef}
                    sitekey={siteKey}
                    theme={theme}
                    size="normal"
                    onVerify={(token) => {
                        onChange(token ?? null);
                    }}
                    onExpire={() => {
                        onExpired();
                        onChange(null);
                    }}
                    onError={(error) => {
                        const message = typeof error === 'string' ? error : undefined;
                        onErrored(message);
                        onChange(null);
                    }}
                    onClose={() => {
                        onExpired();
                        onChange(null);
                    }}
                />
            );
        }, [provider, siteKey, theme, onChange, onExpired, onErrored]);

        if (!content) {
            return null;
        }

        const minHeight = provider === 'RECAPTCHA' ? 78 : undefined;

        return (
            <div style={{...WRAPPER_STYLE, minHeight}}>
                {content}
            </div>
        );
    },
);

CaptchaChallenge.displayName = 'CaptchaChallenge';

export default CaptchaChallenge;