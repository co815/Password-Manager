import {beforeEach, describe, expect, it, vi} from 'vitest';
import {createRef} from 'react';
import {render, waitFor} from '@testing-library/react';

import CaptchaChallenge, {type CaptchaHandle} from '../../components/homePage/CaptchaChallenge';

describe('CaptchaChallenge', () => {
    beforeEach(() => {
        vi.restoreAllMocks();
        delete (window as typeof window & {grecaptcha?: unknown}).grecaptcha;
        delete (window as typeof window & {hcaptcha?: unknown}).hcaptcha;
    });

    it('supports the reCAPTCHA provider', async () => {
        const readyCallbacks: Array<() => void> = [];
        const renderOptions: Array<{
            sitekey: string;
            theme?: 'light' | 'dark';
            callback: (token: string | null) => void;
            'error-callback': () => void;
            'expired-callback': () => void;
        }> = [];

        const reset = vi.fn();
        const renderMock = vi.fn((_container: HTMLElement, options) => {
            renderOptions.push(options);
            return 7;
        });

        (window as typeof window & {grecaptcha: unknown}).grecaptcha = {
            ready: (cb: () => void) => {
                readyCallbacks.push(cb);
                cb();
            },
            render: renderMock,
            reset,
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
                onChange={onChange}
                onExpired={onExpired}
                onErrored={onErrored}
            />,
        );

        const [{callback, 'error-callback': errorCb, 'expired-callback': expiredCb}] =
            renderOptions.length > 0
                ? renderOptions
                : (await waitFor(() => {
                    expect(renderOptions.length).toBeGreaterThan(0);
                    return renderOptions;
                }));

        callback('recaptcha-token');
        expiredCb();
        errorCb();
        ref.current?.reset();

        expect(renderMock).toHaveBeenCalledTimes(1);
        expect(renderMock.mock.calls[0][0]).toBeInstanceOf(HTMLElement);
        expect(renderMock.mock.calls[0][1].sitekey).toBe('recaptcha-site');
        expect(onChange).toHaveBeenCalledWith('recaptcha-token');
        expect(onExpired).toHaveBeenCalledTimes(1);
        expect(onErrored).toHaveBeenCalledTimes(1);
        expect(reset).toHaveBeenCalledWith(7);
    });

    it('supports the hCAPTCHA provider', async () => {
        const renderOptions: Array<{
            sitekey: string;
            theme?: 'light' | 'dark';
            callback: (token: string | null) => void;
            'error-callback': (error?: string) => void;
            'expired-callback': () => void;
        }> = [];

        const reset = vi.fn();
        const remove = vi.fn();
        const renderMock = vi.fn((_container: HTMLElement, options) => {
            renderOptions.push(options);
            return 'widget-1';
        });

        (window as typeof window & {hcaptcha: unknown}).hcaptcha = {
            render: renderMock,
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
                onChange={onChange}
                onExpired={onExpired}
                onErrored={onErrored}
            />,
        );

        const [{callback, 'error-callback': errorCb, 'expired-callback': expiredCb}] =
            renderOptions.length > 0
                ? renderOptions
                : (await waitFor(() => {
                    expect(renderOptions.length).toBeGreaterThan(0);
                    return renderOptions;
                }));

        callback('hcaptcha-token');
        expiredCb();
        errorCb('bad-request');
        ref.current?.reset();

        expect(renderMock).toHaveBeenCalledTimes(1);
        expect(renderMock.mock.calls[0][0]).toBeInstanceOf(HTMLElement);
        expect(renderMock.mock.calls[0][1].sitekey).toBe('hcaptcha-site');
        expect(onChange).toHaveBeenCalledWith('hcaptcha-token');
        expect(onExpired).toHaveBeenCalledTimes(1);
        expect(onErrored).toHaveBeenCalledWith('bad-request');
        expect(reset).toHaveBeenCalledWith('widget-1');
        expect(remove).not.toHaveBeenCalled();
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
