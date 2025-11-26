import {act, fireEvent, render, screen} from '@testing-library/react';
import {MemoryRouter} from 'react-router-dom';
import {forwardRef, useImperativeHandle, type ReactNode} from 'react';
import {beforeEach, describe, expect, it, vi} from 'vitest';

import LoginCard from '../../components/homePage/LoginCard';
import {AuthContext} from '../../auth/auth-context';
import {CryptoContext} from '../../lib/crypto/crypto-context';

const {rememberDekMock, restoreDekMock} = vi.hoisted(() => ({
    rememberDekMock: vi.fn(),
    restoreDekMock: vi.fn(),
}));

vi.mock('../../lib/crypto/dek-storage', () => ({
    rememberDek: rememberDekMock,
    restoreDek: restoreDekMock,
}));

vi.mock('../../lib/crypto', () => ({
    generateLoginHash: vi.fn(),
    fromB64: vi.fn(),
    forgetDek: vi.fn(),
    forgetAllDek: vi.fn(),
}));

type CaptchaConfig = {
    config: {enabled: boolean; provider: 'RECAPTCHA'; siteKey: string};
    loading: boolean;
    error: null;
    refresh: () => Promise<void>;
};

vi.mock('../../lib/hooks/useCaptchaConfig', () => ({
    default: (): CaptchaConfig => ({
        config: {
            enabled: true,
            provider: 'RECAPTCHA',
            siteKey: 'test-key',
        },
        loading: false,
        error: null,
        refresh: vi.fn(),
    }),
}));

const captchaMocks = vi.hoisted(() => {
    let latestProps: Record<string, unknown> | null = null;
    return {
        setProps: (props: Record<string, unknown>) => {
            latestProps = props;
        },
        getProps: () => latestProps,
        clearProps: () => {
            latestProps = null;
        },
        resetSpy: vi.fn(),
    };
});

vi.mock('../../components/homePage/CaptchaChallenge', () => ({
    default: forwardRef<Record<string, unknown>, Record<string, unknown>>((props, ref) => {
        captchaMocks.setProps(props);
        useImperativeHandle(ref, () => ({reset: captchaMocks.resetSpy}));
        return <div data-testid="mock-captcha"/>;
    }),
}));

function Wrapper({children}: {children: ReactNode}) {
    return (
        <MemoryRouter>
            <AuthContext.Provider
                value={{
                    user: null,
                    loading: false,
                    loggingOut: false,
                    sessionRestored: false,
                    login: vi.fn(),
                    logout: vi.fn(),
                    refresh: vi.fn(),
                }}
            >
                <CryptoContext.Provider
                    value={{
                        dek: null,
                        locked: true,
                        hadDek: false,
                        setDEK: vi.fn(),
                        lockNow: vi.fn(),
                        disarm: vi.fn(),
                    }}
                >
                    {children}
                </CryptoContext.Provider>
            </AuthContext.Provider>
        </MemoryRouter>
    );
}

beforeEach(() => {
    captchaMocks.resetSpy.mockClear();
    captchaMocks.clearProps();
    rememberDekMock.mockReset();
    restoreDekMock.mockReset();
    rememberDekMock.mockResolvedValue(undefined);
    restoreDekMock.mockResolvedValue(null);
});

describe('LoginCard captcha', () => {
    it('renders captcha challenge when enabled', async () => {
        render(<LoginCard />, {wrapper: Wrapper});
        expect(await screen.findByTestId('mock-captcha')).toBeInTheDocument();
    });

    it('allows completing captcha before entering credentials', async () => {
        render(<LoginCard />, {wrapper: Wrapper});

        const props = captchaMocks.getProps() as {
            onChange?: (token: string | null) => void;
        } | null;

        await act(async () => {
            props?.onChange?.('captcha-token');
        });

        expect(captchaMocks.resetSpy).not.toHaveBeenCalled();

        const [emailField] = screen.getAllByLabelText(/Email or username/i);
        fireEvent.change(emailField, {target: {value: 'user@example.com'}});

        expect(captchaMocks.resetSpy).not.toHaveBeenCalled();
    });

    it('does not reset captcha while editing credentials', async () => {
        render(<LoginCard />, {wrapper: Wrapper});

        const [emailField] = screen.getAllByLabelText(/Email or username/i);
        const [passwordField] = screen.getAllByLabelText(/Master Password/i);

        const props = captchaMocks.getProps() as {
            onChange?: (token: string | null) => void;
        } | null;

        await act(async () => {
            props?.onChange?.('captcha-token');
        });

        fireEvent.change(emailField, {target: {value: 'user@example.com'}});
        expect(captchaMocks.resetSpy).not.toHaveBeenCalled();

        fireEvent.change(passwordField, {target: {value: 'super-secret'}});
        expect(captchaMocks.resetSpy).not.toHaveBeenCalled();

        fireEvent.change(emailField, {target: {value: 'other@example.com'}});
        expect(captchaMocks.resetSpy).not.toHaveBeenCalled();
    });
}); 
