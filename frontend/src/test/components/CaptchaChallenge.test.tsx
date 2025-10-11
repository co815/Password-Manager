import {createRef} from 'react';
import {render, waitFor} from '@testing-library/react';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';

import CaptchaChallenge, {type CaptchaHandle} from '../../components/homePage/CaptchaChallenge';

type RecaptchaRenderOptions = {
    sitekey: string;
    theme?: string;
    callback?: (token: string) => void;
    'expired-callback'?: () => void;
    'error-callback'?: () => void;
};

type HcaptchaRenderOptions = {
    sitekey: string;
    theme?: string;
    callback?: (token: string | null) => void;
    'expired-callback'?: () => void;
    'error-callback'?: (error?: string) => void;
    'close-callback'?: () => void;
};

describe('CaptchaChallenge', () => {
    beforeEach(() => {
        delete (window as typeof window & {grecaptcha?: unknown}).grecaptcha;
        delete (window as typeof window & {hcaptcha?: unknown}).hcaptcha;
    });

    afterEach(() => {
        delete (window as typeof window & {grecaptcha?: unknown}).grecaptcha;
        delete (window as typeof window & {hcaptcha?: unknown}).hcaptcha;
    });

    it('renders reCAPTCHA and forwards events', async () => {
        const ready = vi.fn((cb: () => void) => cb());
        const reset = vi.fn();
        const remove = vi.fn();
        let renderOptions: RecaptchaRenderOptions | null = null;
        const renderWidget = vi.fn((container: HTMLElement, options: RecaptchaRenderOptions) => {
            renderOptions = options;
            container.dataset.rendered = 'true';
            return 7;
        });

        (window as typeof window & {grecaptcha?: unknown}).grecaptcha = {
            ready,
            render: renderWidget,
            reset,
            remove,
        };

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
            expect(renderWidget).toHaveBeenCalled();
        });

        expect(ready).toHaveBeenCalledTimes(1);
        expect(renderWidget).toHaveBeenCalledTimes(1);
        expect(renderWidget.mock.calls[0][0]).toBeInstanceOf(HTMLElement);
        expect(renderOptions?.sitekey).toBe('recaptcha-site');
        expect(renderOptions?.theme).toBe('dark');

        renderOptions?.callback?.('recaptcha-token');
        renderOptions?.['expired-callback']?.();
        renderOptions?.['error-callback']?.();
        ref.current?.reset();

        expect(onChange).toHaveBeenCalledWith('recaptcha-token');
        expect(onExpired).toHaveBeenCalledTimes(1);
        expect(onErrored).toHaveBeenCalledTimes(1);
        expect(reset).toHaveBeenCalledWith(7);
    });

    it('renders hCaptcha and forwards events', async () => {
        const reset = vi.fn();
        const remove = vi.fn();
        let renderOptions: HcaptchaRenderOptions | null = null;
        const renderWidget = vi.fn((container: HTMLElement, options: HcaptchaRenderOptions) => {
            renderOptions = options;
            container.dataset.rendered = 'true';
            return 'widget-id';
        });

        (window as typeof window & {hcaptcha?: unknown}).hcaptcha = {
            render: renderWidget,
            reset,
            remove,
        };

        const onChange = vi.fn();
        const onExpired = vi.fn();
        const onErrored = vi.fn();
        const ref = createRef<CaptchaHandle>();

        render(
            <CaptchaChallenge
                ref={ref}
                provider="HCAPTCHA"
                siteKey="hcaptcha-site"
                theme="light"
                onChange={onChange}
                onExpired={onExpired}
                onErrored={onErrored}
            />,
        );

        await waitFor(() => {
            expect(renderWidget).toHaveBeenCalled();
        });

        expect(renderWidget).toHaveBeenCalledTimes(1);
        expect(renderWidget.mock.calls[0][0]).toBeInstanceOf(HTMLElement);
        expect(renderOptions?.sitekey).toBe('hcaptcha-site');
        expect(renderOptions?.theme).toBe('light');

        renderOptions?.callback?.('hcaptcha-token');
        renderOptions?.['expired-callback']?.();
        renderOptions?.['error-callback']?.('bad-request');
        renderOptions?.['close-callback']?.();
        ref.current?.reset();

        expect(onChange).toHaveBeenCalledWith('hcaptcha-token');
        expect(onExpired).toHaveBeenCalledTimes(2);
        expect(onErrored).toHaveBeenCalledWith('bad-request');
        expect(reset).toHaveBeenCalledWith('widget-id');
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
