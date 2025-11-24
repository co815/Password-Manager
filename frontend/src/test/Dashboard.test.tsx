import {useState, type ReactNode} from 'react';
import {Buffer} from 'node:buffer';
import {configure, fireEvent, render, screen, waitFor, within} from '@testing-library/react';
import Dashboard from '../pages/Dashboard';
import {AuthContext, type AuthContextValue} from '../auth/auth-context';
import {CryptoContext, type CryptoContextValue} from '../lib/crypto/crypto-context';
import type {VaultItemRequest, PublicUser, VaultItem} from '../lib/api';
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
    deleteCredentialMock,
    listVaultMock,
    createVaultMock,
    updateVaultMock,
    deleteVaultMock,
    updateVaultMetadataMock,
    deriveKekMock,
    unwrapDekMock,
    makeVerifierMock,
    rememberDekMock,
    restoreDekMock,
} = vi.hoisted(() => ({
    fetchCredentialsMock: vi.fn(),
    deleteCredentialMock: vi.fn(),
    listVaultMock: vi.fn(),
    createVaultMock: vi.fn(),
    updateVaultMock: vi.fn(),
    deleteVaultMock: vi.fn(),
    updateVaultMetadataMock: vi.fn(),
    deriveKekMock: vi.fn(),
    unwrapDekMock: vi.fn(),
    makeVerifierMock: vi.fn(),
    rememberDekMock: vi.fn(),
    restoreDekMock: vi.fn(),
})) as {
    fetchCredentialsMock: Mock;
    deleteCredentialMock: Mock;
    listVaultMock: Mock;
    createVaultMock: Mock;
    updateVaultMock: Mock;
    deleteVaultMock: Mock;
    updateVaultMetadataMock: Mock;
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
            deleteCredential: deleteCredentialMock,
            listVault: listVaultMock,
            createVault: createVaultMock,
            updateVault: updateVaultMock,
            deleteVault: deleteVaultMock,
            updateVaultMetadata: updateVaultMetadataMock,
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

        // Setup default mocks
        fetchCredentialsMock.mockResolvedValue({credentials: []});
        listVaultMock.mockResolvedValue([]);
        deleteCredentialMock.mockResolvedValue(undefined);
        deleteVaultMock.mockResolvedValue({ ok: true });

        createVaultMock.mockResolvedValue({
            id: 'item-created-default',
            titleCipher: base64Encode('Service'),
            titleNonce: 'nonce',
            usernameCipher: 'u-cipher',
            usernameNonce: 'u-nonce',
            passwordCipher: 'p-cipher',
            passwordNonce: 'p-nonce',
            favorite: false,
            collections: []
        });

        updateVaultMock.mockResolvedValue({
            id: 'item-updated-default',
            titleCipher: base64Encode('Service'),
            titleNonce: 'nonce',
            usernameCipher: 'u-cipher',
            usernameNonce: 'u-nonce',
            passwordCipher: 'p-cipher',
            passwordNonce: 'p-nonce',
            favorite: false,
            collections: []
        });

        updateVaultMetadataMock.mockResolvedValue({
            id: 'item-meta-default',
            titleCipher: base64Encode('Service'),
            titleNonce: 'nonce',
            usernameCipher: 'u-cipher',
            usernameNonce: 'u-nonce',
            passwordCipher: 'p-cipher',
            passwordNonce: 'p-nonce',
            favorite: false,
            collections: []
        });

        deriveKekMock.mockResolvedValue('derived-kek' as unknown as CryptoKey);
        unwrapDekMock.mockResolvedValue(fakeDek);
        makeVerifierMock.mockResolvedValue('mock-verifier');
        rememberDekMock.mockResolvedValue(undefined);
        restoreDekMock.mockResolvedValue(null);
    });

    it('requests master password when adding a credential without a DEK and unlocks the vault', async () => {
        renderDashboard({initialDek: null, initialLocked: false});

        const [addButton] = await screen.findAllByTitle('Add item');
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
            expect(screen.getByRole('dialog', {name: 'Add item'})).toBeInTheDocument();
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

        const [addButton] = await screen.findAllByTitle('Add item');
        fireEvent.click(addButton);
        const titleField = screen.getByLabelText('Title');
        const usernameField = screen.getByLabelText('Username / Email');
        const passwordField = screen.getByLabelText('Password');
        const urlField = screen.getByLabelText('Website (optional)');

        fireEvent.change(titleField, {target: {value: '  Example Service  '}});
        fireEvent.change(usernameField, {target: {value: 'alice@example.com'}});
        fireEvent.change(passwordField, {target: {value: 'Secret123!'}});
        fireEvent.change(urlField, {target: {value: 'https://example.com'}});

        fireEvent.click(screen.getByRole('button', {name: 'Save'}));

        await waitFor(() => {
            expect(createVaultMock).toHaveBeenCalledTimes(1);
        });

        const createPayload = createVaultMock.mock.calls[0]?.[0] as VaultItemRequest;
        expect(createPayload).toMatchObject({
            url: 'https://example.com',
        });
        expect(createPayload.titleCipher).toBeDefined();
        expect(createPayload.usernameCipher).toBeDefined();
        expect(createPayload.passwordCipher).toBeDefined();

        await screen.findByRole('heading', {name: 'Example Service'});

        const editButtons = screen.getAllByTitle('Edit item');
        const activeEditButton = editButtons.find((button) => !(button as HTMLButtonElement).disabled)
            ?? editButtons[0];
        fireEvent.click(activeEditButton);

        await waitFor(() => {
            expect(screen.getByRole('dialog', {name: 'Edit item'})).toBeInTheDocument();
        });

        const editTitleField = screen.getByLabelText('Title');
        fireEvent.change(editTitleField, {target: {value: ''}});
        fireEvent.change(editTitleField, {target: {value: 'Updated Service'}});

        fireEvent.click(screen.getByRole('button', {name: 'Save changes'}));

        await waitFor(() => {
            expect(updateVaultMock).toHaveBeenCalledWith('item-created-default', expect.objectContaining({

            }));
        });
    }, 15000);

    it('generates a password from the menu and reveals it in the dialog', async () => {
        renderDashboard({initialDek: fakeDek, initialLocked: false});

        const [addButton] = await screen.findAllByTitle('Add item');
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

    it('lists vault items correctly', async () => {
        const vaultItems: VaultItem[] = [
            {
                id: 'item-simple',
                userId: 'user-1',
                titleCipher: base64Encode('Simple Item'),
                titleNonce: base64Encode('n1'),
                usernameCipher: base64Encode('user'),
                usernameNonce: base64Encode('n2'),
                passwordCipher: base64Encode('pass'),
                passwordNonce: base64Encode('n3'),
                favorite: false,
                collections: [],
                url: 'https://example.com'
            }
        ];

        fetchCredentialsMock.mockResolvedValue({credentials: []});

        listVaultMock.mockImplementation(() => Promise.resolve(vaultItems));

        renderDashboard({initialDek: fakeDek, initialLocked: false});

        await screen.findAllByText('Simple Item');
    });
});
