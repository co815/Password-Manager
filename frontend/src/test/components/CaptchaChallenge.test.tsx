import {describe, expect, it, vi, beforeEach} from 'vitest';
import {createRef, forwardRef, useImperativeHandle} from 'react';
import {fireEvent, render} from '@testing-library/react';

import CaptchaChallenge, {type CaptchaHandle} from '../../components/homePage/CaptchaChallenge';

const recaptchaReset = vi.fn();
const hcaptchaReset = vi.fn();

type RecaptchaMockProps = {
    sitekey?: string;
    theme?: 'light' | 'dark';
    onChange?: (token: string | null) => void;
    onExpired?: () => void;
    onErrored?: (message?: string) => void;
};

type HCaptchaMockProps = {
    sitekey?: string;
    theme?: 'light' | 'dark';
    onVerify?: (token: string) => void;
    onExpire?: () => void;
    onChalExpired?: () => void;
    onError?: (message: string) => void;
};

vi.mock('react-google-recaptcha', () => {
    const MockRecaptcha = forwardRef< {reset: () => void}, RecaptchaMockProps>((props, ref) => {
        useImperativeHandle(ref, () => ({reset: recaptchaReset}));
        return (
            <button
                data-testid="recaptcha"
                type="button"
                onClick={() => props.onChange?.('recaptcha-token')}
                onDoubleClick={() => props.onExpired?.()}
                onContextMenu={(event) => {
                    event.preventDefault();
                    props.onErrored?.();
                }}
            />
        );
    });
    return {default: MockRecaptcha};
});

vi.mock('@hcaptcha/react-hcaptcha', () => {
    const MockHCaptcha = forwardRef<{ resetCaptcha: () => void }, HCaptchaMockProps>((props, ref) => {
        useImperativeHandle(ref, () => ({resetCaptcha: hcaptchaReset}));
        return (
            <button
                data-testid="hcaptcha"
                type="button"
                onClick={() => props.onVerify?.('hcaptcha-token')}
                onDoubleClick={() => props.onExpire?.()}
                onMouseEnter={() => props.onChalExpired?.()}
                onContextMenu={(event) => {
                    event.preventDefault();
                    props.onError?.('bad-request');
                }}
            />
        );
    });
    return {default: MockHCaptcha};
});

describe('CaptchaChallenge', () => {
    beforeEach(() => {
        recaptchaReset.mockClear();
        hcaptchaReset.mockClear();
    });

    it('supports the reCAPTCHA provider', () => {
        const onChange = vi.fn();
        const onExpired = vi.fn();
        const onErrored = vi.fn();
        const ref = createRef<CaptchaHandle>();

        const {getByTestId} = render(
            <CaptchaChallenge
                ref={ref}
                provider="RECAPTCHA"
                siteKey="recaptcha-site"
                onChange={onChange}
                onExpired={onExpired}
                onErrored={onErrored}
            />,
        );

        const challenge = getByTestId('recaptcha');
        fireEvent.click(challenge);
        fireEvent.dblClick(challenge);
        fireEvent.contextMenu(challenge);
        ref.current?.reset();

        expect(onChange).toHaveBeenCalledWith('recaptcha-token');
        expect(onExpired).toHaveBeenCalledTimes(1);
        expect(onErrored).toHaveBeenCalledTimes(1);
        expect(recaptchaReset).toHaveBeenCalledTimes(1);
    });

    it('supports the hCAPTCHA provider', () => {
        const onChange = vi.fn();
        const onExpired = vi.fn();
        const onErrored = vi.fn();
        const ref = createRef<CaptchaHandle>();

        const {getByTestId} = render(
            <CaptchaChallenge
                ref={ref}
                provider="HCAPTCHA"
                siteKey="hcaptcha-site"
                onChange={onChange}
                onExpired={onExpired}
                onErrored={onErrored}
            />,
        );

        const challenge = getByTestId('hcaptcha');
        fireEvent.click(challenge);
        fireEvent.dblClick(challenge);
        fireEvent.contextMenu(challenge);
        ref.current?.reset();

        expect(onChange).toHaveBeenCalledWith('hcaptcha-token');
        expect(onExpired).toHaveBeenCalledTimes(1);
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
