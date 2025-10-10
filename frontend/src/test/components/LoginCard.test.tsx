import {render, screen} from '@testing-library/react';
import {MemoryRouter} from 'react-router-dom';
import {forwardRef, type ReactNode} from 'react';
import {describe, expect, it, vi} from 'vitest';

import LoginCard from '../../components/homePage/LoginCard';
import {AuthContext} from '../../auth/auth-context';
import {CryptoContext} from '../../lib/crypto/crypto-context';

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

vi.mock('../../components/homePage/CaptchaChallenge', () => ({
    default: forwardRef((_props, _ref) => <div data-testid="mock-captcha" />),
}));

function Wrapper({children}: {children: ReactNode}) {
    return (
        <MemoryRouter>
            <AuthContext.Provider
                value={{
                    user: null,
                    loading: false,
                    loggingOut: false,
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

describe('LoginCard captcha', () => {
    it('renders captcha challenge when enabled', async () => {
        render(<LoginCard />, {wrapper: Wrapper});
        expect(await screen.findByTestId('mock-captcha')).toBeInTheDocument();
    });
});