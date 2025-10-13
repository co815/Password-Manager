import {render, waitFor} from '@testing-library/react';
import {useEffect} from 'react';
import {beforeEach, describe, expect, it, vi, type Mock} from 'vitest';

import useCaptchaConfig, {resetCachedCaptchaConfig} from '../../lib/hooks/useCaptchaConfig';
import {api} from '../../lib/api';

type CaptchaConfig = {
    config: ReturnType<typeof useCaptchaConfig>['config'];
    loading: boolean;
};

vi.mock('../../lib/api', () => ({
    api: {
        getCaptchaConfig: vi.fn(),
    },
}));

function Consumer({onUpdate}: {onUpdate: (value: CaptchaConfig) => void}) {
    const value = useCaptchaConfig();
    useEffect(() => {
        onUpdate({config: value.config, loading: value.loading});
    }, [value.config, value.loading, onUpdate]);
    return null;
}

describe('useCaptchaConfig', () => {
    beforeEach(() => {
        resetCachedCaptchaConfig();
        vi.clearAllMocks();
    });

    it('normalizes provider casing and trims site keys', async () => {
        const getCaptchaConfig = api.getCaptchaConfig as Mock;
        getCaptchaConfig.mockResolvedValue({
            enabled: true,
            provider: 'recaptcha',
            siteKey: '  my-key  ',
        });

        const updates: CaptchaConfig[] = [];
        render(<Consumer onUpdate={(value) => updates.push(value)} />);

        await waitFor(() => {
            expect(updates.at(-1)?.loading).toBe(false);
        });

        const final = updates.at(-1);
        expect(final?.config?.provider).toBe('RECAPTCHA');
        expect(final?.config?.siteKey).toBe('my-key');
        expect(final?.config?.enabled).toBe(true);
    });

    it('falls back to disabled config when provider is unknown', async () => {
        const getCaptchaConfig = api.getCaptchaConfig as Mock;
        getCaptchaConfig.mockResolvedValue({
            enabled: true,
            provider: 'something-else',
            siteKey: '  ',
        });

        const updates: CaptchaConfig[] = [];
        render(<Consumer onUpdate={(value) => updates.push(value)} />);

        await waitFor(() => {
            expect(updates.at(-1)?.loading).toBe(false);
        });

        const final = updates.at(-1);
        expect(final?.config?.provider).toBe('NONE');
        expect(final?.config?.siteKey).toBeNull();
        expect(final?.config?.enabled).toBe(false);
    });

});
