import {createRef} from 'react';
import {render, waitFor} from '@testing-library/react';
import {beforeEach, describe, expect, it, vi} from 'vitest';

import CaptchaChallenge, {type CaptchaHandle} from '../../components/homePage/CaptchaChallenge';

let recaptchaProps: Record<string, unknown> | null = null;
const recaptchaReset = vi.fn();

vi.mock('react-google-recaptcha', async () => {
    const React = await import('react');
    const {forwardRef, useImperativeHandle} = React;
    const MockReCaptcha = forwardRef((props: Record<string, unknown>, ref) => {
        recaptchaProps = props;
        useImperativeHandle(ref, () => ({reset: recaptchaReset}));
        return React.createElement('div', {'data-testid': 'recaptcha-mock'});
    });
    return {__esModule: true, default: MockReCaptcha};
});

let hcaptchaProps: Record<string, unknown> | null = null;
const hcaptchaReset = vi.fn();

vi.mock('@hcaptcha/react-hcaptcha', async () => {
    const React = await import('react');
    const {forwardRef, useImperativeHandle} = React;
    const MockHCaptcha = forwardRef((props: Record<string, unknown>, ref) => {
        hcaptchaProps = props;
        useImperativeHandle(ref, () => ({resetCaptcha: hcaptchaReset}));
        return React.createElement('div', {'data-testid': 'hcaptcha-mock'});
    });
    return {__esModule: true, default: MockHCaptcha};
});

describe('CaptchaChallenge', () => {
    beforeEach(() => {
        recaptchaProps = null;
        hcaptchaProps = null;
        recaptchaReset.mockClear();
        hcaptchaReset.mockClear();
    });

    it('renders reCAPTCHA and forwards events', async () => {
        const onChange = vi.fn();
        const onExpired = vi.fn();
        const onErrored = vi.fn();
        const ref = createRef<CaptchaHandle>();

        render(
            <CaptchaChallenge
                ref={ref}
                provider="RECAPTCHA"
                siteKey="recaptcha-site"
                theme="dark"
                onChange={onChange}
                onExpired={onExpired}
                onErrored={onErrored}
            />,
        );

        await waitFor(() => {
            expect(recaptchaProps).not.toBeNull();
        });

        const props = recaptchaProps as {
            sitekey: string;
            theme?: string;
            onChange?: (token: string | null) => void;
            onExpired?: () => void;
            onErrored?: () => void;
        };

        expect(props.sitekey).toBe('recaptcha-site');
        expect(props.theme).toBe('dark');

        props.onChange?.('recaptcha-token');
        props.onExpired?.();
        props.onErrored?.();
        ref.current?.reset();

        expect(onChange).toHaveBeenCalledWith('recaptcha-token');
        expect(onExpired).toHaveBeenCalledTimes(1);
        expect(onErrored).toHaveBeenCalledTimes(1);
        expect(recaptchaReset).toHaveBeenCalledTimes(1);
    });

    it('renders hCaptcha and forwards events', async () => {

        const onChange = vi.fn();
        const onExpired = vi.fn();
        const onErrored = vi.fn();
        const ref = createRef<CaptchaHandle>();

        render(
            <CaptchaChallenge
                ref={ref}
                provider="HCAPTCHA"
                siteKey="hcaptcha-site"
                onChange={onChange}
                onExpired={onExpired}
                onErrored={onErrored}
            />,
        );

        await waitFor(() => {
            expect(hcaptchaProps).not.toBeNull();
        });

        const props = hcaptchaProps as {
            sitekey: string;
            onVerify?: (token: string | null) => void;
            onExpire?: () => void;
            onError?: (error: unknown) => void;
            onClose?: () => void;
        };

        expect(props.sitekey).toBe('hcaptcha-site');

        props.onVerify?.('hcaptcha-token');
        props.onExpire?.();
        props.onError?.('bad-request');
        props.onClose?.();
        ref.current?.reset();

        expect(onChange).toHaveBeenCalledWith('hcaptcha-token');
        expect(onExpired).toHaveBeenCalledTimes(2);
        expect(onErrored).toHaveBeenCalledWith('bad-request');
        expect(hcaptchaReset).toHaveBeenCalledTimes(1);
    });

    it('renders nothing when disabled', () => {
        const {container} = render(
            <CaptchaChallenge
                provider="NONE"
                siteKey=""
                onChange={() => undefined}
                onExpired={() => undefined}
                onErrored={() => undefined}
            />,
        );

        expect(container.firstChild).toBeNull();
    });
});
