import {useState, type ReactNode} from 'react';
import {Buffer} from 'node:buffer';
import {configure, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import Dashboard from '../pages/Dashboard';
import {AuthContext, type AuthContextValue} from '../auth/auth-context';
import {CryptoContext, type CryptoContextValue} from '../lib/crypto/crypto-context';
import type {CreateCredentialRequest, PublicCredential, PublicUser} from '../lib/api';
import {describe, beforeAll, beforeEach, vi, it, expect, type Mock} from 'vitest';
import {MemoryRouter} from 'react-router-dom';
import {ThemeProvider, createTheme} from '@mui/material/styles';

const testTheme = createTheme({
    transitions: {
        create: () => 'none',
        duration: {
            shortest: 0,
            shorter: 0,
            short: 0,
            standard: 0,
            complex: 0,
            enteringScreen: 0,
            leavingScreen: 0,
        },
    },
});

const {
    fetchCredentialsMock,
    createCredentialMock,
    updateCredentialMock,
    deleteCredentialMock,
    updateCredentialFavoriteMock,
    deriveKekMock,
    unwrapDekMock,
    makeVerifierMock,
    rememberDekMock,
    restoreDekMock,
} = vi.hoisted(() => ({
    fetchCredentialsMock: vi.fn(),
    createCredentialMock: vi.fn(),
    updateCredentialMock: vi.fn(),
    deleteCredentialMock: vi.fn(),
    updateCredentialFavoriteMock: vi.fn(),
    deriveKekMock: vi.fn(),
    unwrapDekMock: vi.fn(),
    makeVerifierMock: vi.fn(),
    rememberDekMock: vi.fn(),
    restoreDekMock: vi.fn(),
})) as {
    fetchCredentialsMock: Mock;
    createCredentialMock: Mock;
    updateCredentialMock: Mock;
    deleteCredentialMock: Mock;
    updateCredentialFavoriteMock: Mock;
    deriveKekMock: Mock;
    unwrapDekMock: Mock;
    makeVerifierMock: Mock;
    rememberDekMock: Mock;
    restoreDekMock: Mock;
};

vi.mock('../lib/api', async () => {
    const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
    return {
        ...actual,
        api: {
            ...actual.api,
            fetchCredentials: fetchCredentialsMock,
            createCredential: createCredentialMock,
            updateCredential: updateCredentialMock,
            deleteCredential: deleteCredentialMock,
            updateCredentialFavorite: updateCredentialFavoriteMock,
        },
    };
});

vi.mock('../lib/crypto/argon2', () => ({
    deriveKEK: deriveKekMock,
    makeVerifier: makeVerifierMock,
}));

vi.mock('../lib/crypto/unwrap', () => ({
    unwrapDEK: unwrapDekMock,
    unwrapDek: unwrapDekMock,
}));

vi.mock('../lib/crypto/dek-storage', () => ({
    rememberDek: rememberDekMock,
    restoreDek: restoreDekMock,
    forgetDek: vi.fn(),
    forgetAllDek: vi.fn(),
}));

vi.mock('@mui/material', async () => {
    const actual = await vi.importActual<typeof import('@mui/material')>('@mui/material');
    const Dialog = (props: import('@mui/material').DialogProps) => (
        <actual.Dialog
            {...props}
            TransitionProps={{...(props.TransitionProps ?? {}), timeout: 0}}
        />
    );

    const Menu = (props: import('@mui/material').MenuProps) => (
        <actual.Menu
            {...props}
            transitionDuration={0}
            TransitionProps={{...(props.TransitionProps ?? {}), timeout: 0}}
        />
    );

    const Snackbar = (props: import('@mui/material').SnackbarProps) => (
        <actual.Snackbar
            {...props}
            TransitionProps={{...(props.TransitionProps ?? {}), timeout: 0}}
            autoHideDuration={props.autoHideDuration ?? null}
        />
    );

    return {
        ...actual,
        Dialog,
        Menu,
        Snackbar,
    };
});

const baseUser: PublicUser = {
    id: 'user-1',
    email: 'user@example.com',
    username: 'test-user',
    saltClient: 'client-salt',
    dekEncrypted: 'encrypted-dek',
    dekNonce: 'dek-nonce',
    avatarData: null,
    mfaEnabled: false,
    masterPasswordLastRotated: null,
    mfaEnabledAt: null,
};

type RenderOptions = {
    user?: PublicUser | null;
    initialDek?: CryptoKey | null;
    initialLocked?: boolean;
};

function TestProviders({children, options = {}}: {children: ReactNode; options?: RenderOptions}) {
    const {user = baseUser, initialDek = null, initialLocked = false} = options;
    const [dek, setDek] = useState<CryptoKey | null>(initialDek);
    const [locked, setLocked] = useState<boolean>(initialLocked);

    const authValue: AuthContextValue = {
        user,
        loading: false,
        loggingOut: false,
        sessionRestored: false,
        login: vi.fn(),
        logout: vi.fn(),
        refresh: vi.fn(),
    };

    const cryptoValue: CryptoContextValue = {
        dek,
        locked,
        hadDek: Boolean(dek),
        setDEK: (key) => {
            setDek(key);
            setLocked(!key);
        },
        lockNow: () => setLocked(true),
        disarm: vi.fn(),
    };

    return (
        <MemoryRouter>
            <ThemeProvider theme={testTheme}>
                <AuthContext.Provider value={authValue}>
                    <CryptoContext.Provider value={cryptoValue}>{children}</CryptoContext.Provider>
                </AuthContext.Provider>
            </ThemeProvider>
        </MemoryRouter>
    );
}

function renderDashboard(options?: RenderOptions) {
    return render(
        <TestProviders options={options}>
            <Dashboard/>
        </TestProviders>,
    );
}

function base64Encode(text: string): string {
    if (typeof globalThis.btoa === 'function') {
        return globalThis.btoa(text);
    }
    return Buffer.from(text, 'utf-8').toString('base64');
}

describe('Dashboard', () => {
    const fakeDek = {} as CryptoKey;

    beforeAll(() => {
        configure({asyncUtilTimeout: 200});
    });

    beforeAll(() => {
        const cryptoStub = {
            getRandomValues: (array: Uint8Array | Uint32Array) => {
                const arr = array;
                for (let i = 0; i < arr.length; i += 1) {
                    arr[i] = (i + 1) % 255;
                }
                return arr;
            },
            subtle: {
                encrypt: async (
                    _algo: AlgorithmIdentifier,
                    _key: CryptoKey,
                    data: ArrayBuffer | Uint8Array,
                ) => {
                    if (data instanceof ArrayBuffer) {
                        return data;
                    }
                    return data.buffer;
                },
                decrypt: async (
                    _algo: AlgorithmIdentifier,
                    _key: CryptoKey,
                    data: ArrayBuffer | Uint8Array,
                ) => {
                    if (data instanceof ArrayBuffer) {
                        return data;
                    }
                    return data.buffer;
                },
            },
        } as unknown as Crypto;

        Object.defineProperty(globalThis, 'crypto', {
            configurable: true,
            value: cryptoStub,
        });

        if (typeof globalThis.atob !== 'function') {
            globalThis.atob = (value: string) => Buffer.from(value, 'base64').toString('binary');
        }
        if (typeof globalThis.btoa !== 'function') {
            globalThis.btoa = (value: string) => Buffer.from(value, 'binary').toString('base64');
        }
    });

    beforeEach(() => {
        vi.clearAllMocks();
        window.localStorage.clear();
        fetchCredentialsMock.mockReset();
        createCredentialMock.mockReset();
        updateCredentialMock.mockReset();
        deleteCredentialMock.mockReset();
        updateCredentialFavoriteMock.mockReset();
        deriveKekMock.mockReset();
        unwrapDekMock.mockReset();
        makeVerifierMock.mockReset();
        fetchCredentialsMock.mockResolvedValue({credentials: []});
        createCredentialMock.mockResolvedValue({
            credentialId: 'cred-1',
            service: 'Service',
            websiteLink: '',
            usernameEncrypted: '',
            usernameNonce: '',
            passwordEncrypted: '',
            passwordNonce: '',
            favorite: false,
        });
        updateCredentialMock.mockResolvedValue({
            credentialId: 'cred-1',
            service: 'Service',
            websiteLink: '',
            usernameEncrypted: '',
            usernameNonce: '',
            passwordEncrypted: '',
            passwordNonce: '',
            favorite: false,
        });
        deleteCredentialMock.mockResolvedValue(undefined);
        updateCredentialFavoriteMock.mockResolvedValue({
            credentialId: 'cred-1',
            service: 'Service',
            websiteLink: '',
            usernameEncrypted: '',
            usernameNonce: '',
            passwordEncrypted: '',
            passwordNonce: '',
            favorite: false,
        });
        deriveKekMock.mockResolvedValue('derived-kek' as unknown as CryptoKey);
        unwrapDekMock.mockResolvedValue(fakeDek);
        makeVerifierMock.mockResolvedValue('mock-verifier');
        rememberDekMock.mockReset();
        restoreDekMock.mockReset();
        rememberDekMock.mockResolvedValue(undefined);
        restoreDekMock.mockResolvedValue(null);
    });

    it('requests master password when adding a credential without a DEK and unlocks the vault', async () => {
        renderDashboard({initialDek: null, initialLocked: false});

        const [addButton] = await screen.findAllByTitle('Add credential');
        fireEvent.click(addButton);
        expect(screen.getByRole('dialog', {name: 'Unlock Vault to Add Credential'})).toBeInTheDocument();

        const passwordField = screen.getByLabelText('Master password');
        fireEvent.change(passwordField, {target: {value: 'super-secret'}});
        fireEvent.click(screen.getByRole('button', {name: 'Unlock'}));

        await waitFor(() => {
            expect(deriveKekMock).toHaveBeenCalledWith('super-secret', baseUser.saltClient);
            expect(unwrapDekMock).toHaveBeenCalled();
            expect(rememberDekMock).toHaveBeenCalledWith(baseUser.id, fakeDek);
        });

        await waitFor(() => {
            expect(screen.queryByRole('dialog', {name: 'Unlock Vault to Add Credential'})).not.toBeInTheDocument();
        });

        await waitFor(() => {
            expect(screen.getByRole('dialog', {name: 'Add credential'})).toBeInTheDocument();
        });
    });

    it('prompts to unlock the vault when signed in without a DEK', async () => {
        renderDashboard({initialDek: null, initialLocked: true});

        await waitFor(() => {
            expect(screen.getByRole('dialog', {name: /unlock vault/i})).toBeInTheDocument();
        });

        fireEvent.click(screen.getByRole('button', {name: 'Cancel'}));

        await waitFor(() => {
            expect(screen.queryByRole('dialog', {name: /unlock vault/i})).not.toBeInTheDocument();
        });

        const unlockButton = await screen.findByTestId('unlock-vault-button');
        fireEvent.click(unlockButton);

        fireEvent.click(screen.getByRole('button', {name: 'Cancel'}));

        await waitFor(() => {
            expect(screen.queryByRole('dialog', {name: /unlock vault/i})).not.toBeInTheDocument();
        });
    });

    it('adds a new credential and allows editing the saved entry', async () => {
        renderDashboard({initialDek: fakeDek, initialLocked: false});

        const [addButton] = await screen.findAllByTitle('Add credential');
        fireEvent.click(addButton);
        const titleField = screen.getByLabelText('Title (service)');
        const usernameField = screen.getByLabelText('Username / Email');
        const passwordField = screen.getByLabelText('Password');
        const urlField = screen.getByLabelText('Website (optional)');

        fireEvent.change(titleField, {target: {value: '  Example Service  '}});
        fireEvent.change(usernameField, {target: {value: 'alice@example.com'}});
        fireEvent.change(passwordField, {target: {value: 'Secret123!'}});
        fireEvent.change(urlField, {target: {value: 'https://example.com'}});

        fireEvent.click(screen.getByRole('button', {name: 'Save'}));

        await waitFor(() => {
            expect(createCredentialMock).toHaveBeenCalledTimes(1);
        });

        const createPayload = createCredentialMock.mock.calls[0]?.[0] as CreateCredentialRequest;
        expect(createPayload).toMatchObject({
            title: '  Example Service  ',
            url: 'https://example.com',
        });
        expect(createPayload.usernameCipher).toBeDefined();
        expect(createPayload.passwordCipher).toBeDefined();

        await screen.findByRole('heading', {name: 'Example Service'});

        const editButtons = screen.getAllByTitle('Edit credential');
        const activeEditButton = editButtons.find((button) => !(button as HTMLButtonElement).disabled)
            ?? editButtons[0];
        fireEvent.click(activeEditButton);

        await waitFor(() => {
            expect(screen.getByRole('dialog', {name: 'Edit credential'})).toBeInTheDocument();
        });

        const editTitleField = screen.getByLabelText('Title (service)');
        fireEvent.change(editTitleField, {target: {value: ''}});
        fireEvent.change(editTitleField, {target: {value: 'Updated Service'}});

        fireEvent.click(screen.getByRole('button', {name: 'Save changes'}));

        await waitFor(() => {
            expect(updateCredentialMock).toHaveBeenCalledWith('cred-1', expect.objectContaining({
                service: 'Updated Service',
            }));
        });

        await screen.findByRole('heading', {name: 'Updated Service'});
    }, 15000);

    it('generates a password from the menu and reveals it in the dialog', async () => {
        renderDashboard({initialDek: fakeDek, initialLocked: false});

        const [addButton] = await screen.findAllByTitle('Add credential');
        fireEvent.click(addButton);
        fireEvent.click(screen.getByLabelText('Generate password'));

        const menuItem = await screen.findByRole('menuitem', {name: /Balanced/});
        fireEvent.click(menuItem);

        await waitFor(() => {
            const passwordInput = screen.getByLabelText('Password') as HTMLInputElement;
            expect(passwordInput.value).not.toBe('');
            expect(passwordInput.type).toBe('text');
        });
    });

    it('filters credentials and manages favorites', async () => {
        const credentials: PublicCredential[] = [
            {
                credentialId: 'cred-mail',
                service: 'Mail',
                websiteLink: 'https://mail.example.com',
                usernameEncrypted: base64Encode('alice'),
                usernameNonce: base64Encode('nonce-1'),
                passwordEncrypted: base64Encode('mail-pass'),
                passwordNonce: base64Encode('nonce-2'),
                favorite: false,
            },
            {
                credentialId: 'cred-git',
                service: 'GitHub',
                websiteLink: 'https://github.com',
                usernameEncrypted: base64Encode('bob'),
                usernameNonce: base64Encode('nonce-3'),
                passwordEncrypted: base64Encode('git-pass'),
                passwordNonce: base64Encode('nonce-4'),
                favorite: false,
            },
        ];

        fetchCredentialsMock.mockResolvedValue({credentials});
        updateCredentialFavoriteMock.mockResolvedValueOnce({
            ...credentials[0],
            favorite: true,
        });

        renderDashboard({initialDek: fakeDek, initialLocked: false});

        const mailNodes = await screen.findAllByText('Mail');
        const mailEntry = mailNodes.find((node) => node.closest('ul'));
        const credentialList = mailEntry?.closest('ul');
        expect(credentialList).not.toBeNull();
        await within(credentialList as HTMLElement).findByText('GitHub');

        const favoriteButtons = screen.getAllByTitle('Add to favorites');
        const activeFavoriteButton = favoriteButtons.find((button) => !(button as HTMLButtonElement).disabled)
            ?? favoriteButtons[0];
        fireEvent.click(activeFavoriteButton);
        await waitFor(() => {
            expect(updateCredentialFavoriteMock).toHaveBeenCalledWith(expect.any(String), true);
        });

        const categoryButtons = screen.getAllByRole('button', {name: /mail\.example\.com/i});
        fireEvent.click(categoryButtons[0]);

        await waitFor(() => {
            const visibleItems = credentialList?.querySelectorAll('[role="button"]') ?? [];
            expect(visibleItems.length).toBe(1);
            expect(within(credentialList as HTMLElement).getByText('Mail')).toBeInTheDocument();
        });
    });
});