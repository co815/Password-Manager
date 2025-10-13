import {StrictMode, createRef} from 'react';
import {act, render, waitFor} from '@testing-library/react';
import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';

import CaptchaChallenge, {type CaptchaHandle} from '../../components/homePage/CaptchaChallenge';

type RecaptchaRenderOptions = {
    sitekey: string;
    theme?: string;
    callback?: (token: string) => void;
    'expired-callback'?: () => void;
    'error-callback'?: () => void;
};

describe('CaptchaChallenge', () => {
    beforeEach(() => {
        delete (window as typeof window & {grecaptcha?: unknown}).grecaptcha;
        document.head.innerHTML = '';
    });

    afterEach(() => {
        delete (window as typeof window & {grecaptcha?: unknown}).grecaptcha;
        document.head.innerHTML = '';
        vi.restoreAllMocks();
    });

    it('renders reCAPTCHA and forwards events', async () => {
        const ready = vi.fn<(cb: () => void) => void>((cb) => cb());
        const reset = vi.fn();
        const remove = vi.fn();
        let renderOptions: RecaptchaRenderOptions | null = null;
        const renderWidget = vi.fn<
            (container: HTMLElement, options: RecaptchaRenderOptions) => number
        >((container, options) => {
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
            <StrictMode>
                <CaptchaChallenge
                    ref={ref}
                    provider="RECAPTCHA"
                    siteKey="recaptcha-site"
                    theme="dark"
                    onChange={onChange}
                    onExpired={onExpired}
                    onErrored={onErrored}
                />
            </StrictMode>,
        );

        await waitFor(() => {
            expect(renderWidget).toHaveBeenCalled();
        });

        expect(ready).toHaveBeenCalledTimes(1);
        expect(renderWidget).toHaveBeenCalledTimes(1);
        expect(renderWidget.mock.calls[0][0]).toBeInstanceOf(HTMLElement);
        expect(renderOptions).not.toBeNull();
        const recaptchaOptions = renderOptions!;
        expect(recaptchaOptions.sitekey).toBe('recaptcha-site');
        expect(recaptchaOptions.theme).toBe('dark');

        recaptchaOptions.callback?.('recaptcha-token');
        recaptchaOptions['expired-callback']?.();
        recaptchaOptions['error-callback']?.();
        ref.current?.reset();

        expect(onChange).toHaveBeenCalledWith('recaptcha-token');
        expect(onExpired).toHaveBeenCalledTimes(1);
        expect(onErrored).toHaveBeenCalledTimes(1);
        expect(reset).toHaveBeenCalledWith(7);
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

    it('loads the reCAPTCHA script when it is not available yet', async () => {
        let createdScript: HTMLScriptElement | null = null;
        const originalCreateElement = document.createElement.bind(document);
        vi.spyOn(document, 'createElement').mockImplementation(((tagName: string) => {
            const element = originalCreateElement(tagName);
            if (tagName === 'script') {
                createdScript = element as HTMLScriptElement;
            }
            return element;
        }) as typeof document.createElement);

        const renderWidget = vi.fn<
            (container: HTMLElement, options: RecaptchaRenderOptions) => number
        >((container, options) => {
            container.dataset.rendered = options.sitekey;
            return 1;
        });

        const ready = vi.fn<(cb: () => void) => void>((cb) => cb());
        const reset = vi.fn();
        const remove = vi.fn();

        const ref = createRef<CaptchaHandle>();
        const onChange = vi.fn();
        const onExpired = vi.fn();
        const onErrored = vi.fn();

        const view = render(
            <StrictMode>
                <CaptchaChallenge
                    ref={ref}
                    provider="RECAPTCHA"
                    siteKey="recaptcha-site"
                    theme="light"
                    onChange={onChange}
                    onExpired={onExpired}
                    onErrored={onErrored}
                />
            </StrictMode>,
        );

        expect(createdScript).not.toBeNull();
        const scriptEl = createdScript!;
        expect(scriptEl.getAttribute('data-captcha-src')).toBe('https://www.google.com/recaptcha/api.js?render=explicit');
        expect(scriptEl.dataset.captchaLoaded).toBe('false');

        (window as typeof window & {grecaptcha?: unknown}).grecaptcha = {
            ready,
            render: renderWidget,
            reset,
            remove,
        };

        await act(async () => {
            scriptEl.dispatchEvent(new Event('load'));
            await Promise.resolve();
        });

        await waitFor(() => {
            expect(renderWidget).toHaveBeenCalledTimes(1);
        });

        expect(scriptEl.dataset.captchaLoaded).toBe('true');
        view.unmount();
    });
});
