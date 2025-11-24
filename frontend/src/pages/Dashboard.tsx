import {useMemo, useState, useEffect, useCallback, useRef} from 'react';
import {useNavigate} from 'react-router-dom';
import type {ChangeEvent, FormEvent, MouseEvent} from 'react';
import {useAuth} from '../auth/auth-context';
import {useCrypto} from '../lib/crypto/crypto-context';
import {api, ApiError, type MfaEnrollmentResponse, type MfaStatusResponse, type PublicCredential, type VaultItem} from '../lib/api';
import {isAuditAdminEmail} from '../lib/accessControl';
import Alert from '@mui/material/Alert';
import {deriveKEK, makeVerifier} from '../lib/crypto/argon2';
import {unwrapDEK} from '../lib/crypto/unwrap';
import {encryptDekWithKek} from '../lib/crypto/keys';
import {deserializeVaultCredentials, serializeVaultCredentials} from '../lib/vault/pack';
import {extractApiErrorDetails} from '../lib/api-error';
import {attestationToJSON, decodeCreationOptions, isWebAuthnSupported} from '../lib/webauthn';
import {rememberDek, restoreDek} from '../lib/crypto/dek-storage';
import * as OTPAuth from 'otpauth';

import {
    Box, Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Divider, Typography,
    Avatar, TextField, IconButton, Card, CardContent, Button, InputAdornment, Tooltip,
    Dialog, DialogTitle, DialogContent, DialogActions, DialogContentText, Snackbar, Stack, LinearProgress,
    CircularProgress,
    Menu, MenuItem, Chip, FormControlLabel, Checkbox,
    useMediaQuery, useTheme
} from '@mui/material';

import {
    Search,
    Note,
    Key,
    Star,
    StarBorder,
    Edit,
    Delete,
    Add as AddIcon,
    Download,
    Visibility,
    VisibilityOff,
    Link as LinkIcon,
    Settings,
    Upload,
    UploadFile,
    DeleteOutline,
    ListAlt,
    ContentCopy,
    AutoFixHigh,
    LockOpen,
    Menu as MenuIcon,
    Logout,
    Timer,
} from '@mui/icons-material';
import {passwordTemplates} from '../lib/passwordTemplates';
import {
    MIN_ACCEPTABLE_PASSWORD_SCORE,
    assessPasswordStrength,
    getPasswordStrengthColor,
    getPasswordStrengthLabel,
} from '../lib/passwordStrength';

const td = new TextDecoder();

async function decryptField(dek: CryptoKey, cipher: string, nonce: string) {
    if (!cipher || !nonce) return '';
    try {
        const ct = Uint8Array.from(atob(cipher), c => c.charCodeAt(0));
        const iv = Uint8Array.from(atob(nonce), c => c.charCodeAt(0));
        const pt = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, dek, ct);
        return td.decode(pt);
    } catch {
        return '*** DECRYPTION ERROR ***';
    }
}

export type Credential = {
    id: string;
    name: string;
    url?: string;
    username: string;
    password: string;
    notes?: string;
    totpSecret?: string;
    favorite: boolean;
    collections: string[];
};

const ALL_CATEGORY_ID = '__all__';
const UNCATEGORIZED_LABEL = 'Uncategorized';

type CategoryItem = {
    id: string;
    label: string;
    count: number;
};

function inferCategoryFromLegacy(name: string, url?: string): string {
    if (url && url.trim()) {
        try {
            const normalized = url.includes('://') ? url : `https://${url}`;
            const parsed = new URL(normalized);
            const hostname = parsed.hostname.replace(/^www\./i, '').trim();
            if (hostname) {
                return hostname;
            }
        } catch {

        }
    }
    if (name && name.trim()) {
        return name.trim();
    }
    return UNCATEGORIZED_LABEL;
}

const te = new TextEncoder();
const toB64 = (buf: ArrayBuffer | Uint8Array) =>
    btoa(String.fromCharCode(...new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer)));
const randIv = (len = 12) => crypto.getRandomValues(new Uint8Array(len));

const ALLOWED_AVATAR_TYPES = ['image/png', 'image/jpeg', 'image/webp'];
const MAX_AVATAR_SIZE = 256 * 1024;

async function encryptField(dek: CryptoKey, text: string) {
    const iv = randIv();
    const ct = await crypto.subtle.encrypt({name: 'AES-GCM', iv}, dek, te.encode(text ?? ''));
    return {cipher: toB64(ct), nonce: toB64(iv)} as { cipher: string; nonce: string };
}

export default function Dashboard() {
    const {user, logout, login, refresh} = useAuth();
    const {dek, locked, hadDek, setDEK} = useCrypto();
    const navigate = useNavigate();

    const theme = useTheme();
    const isMobile = useMediaQuery(theme.breakpoints.down('md'));
    const [mobileOpen, setMobileOpen] = useState(false);
    const [searchExpanded, setSearchExpanded] = useState(false);
    const [userMenuAnchor, setUserMenuAnchor] = useState<null | HTMLElement>(null);
    const userMenuOpen = Boolean(userMenuAnchor);

    const handleDrawerToggle = () => {
        setMobileOpen(!mobileOpen);
    };

    const handleUserMenuOpen = (event: MouseEvent<HTMLElement>) => {
        setUserMenuAnchor(event.currentTarget);
    };

    const handleUserMenuClose = () => {
        setUserMenuAnchor(null);
    };

    const [credentials, setCredentials] = useState<Credential[]>([]);
    const [selected, setSelected] = useState<Credential | null>(null);
    const [favoriteBusy, setFavoriteBusy] = useState(false);

    const [dialogMode, setDialogMode] = useState<'add' | 'edit' | null>(null);
    const [editingTarget, setEditingTarget] = useState<Credential | null>(null);
    const [pendingDialogMode, setPendingDialogMode] = useState<'add' | 'edit' | null>(null);
    const [pendingEditTarget, setPendingEditTarget] = useState<Credential | null>(null);
    const openDialog = dialogMode !== null;

    const [showUnlockDialog, setShowUnlockDialog] = useState(false);
    const [autoPromptedUnlock, setAutoPromptedUnlock] = useState(false);
    const restoreAttemptedRef = useRef<string | null>(null);
    const [unlockPassword, setUnlockPassword] = useState('');
    const [showUnlockPwd, setShowUnlockPwd] = useState(false);
    const [unlockBusy, setUnlockBusy] = useState(false);
    const [unlockError, setUnlockError] = useState<string | null>(null);
    const [showSelectedPassword, setShowSelectedPassword] = useState(false);

    const [title, setTitle] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [url, setUrl] = useState('');
    const [notes, setNotes] = useState('');
    const [tags, setTags] = useState('');
    const [totpSecret, setTotpSecret] = useState('');
    const [showPwd, setShowPwd] = useState(false);
    const [generatorAnchorEl, setGeneratorAnchorEl] = useState<null | HTMLElement>(null);
    const generatorMenuOpen = Boolean(generatorAnchorEl);
    const [busy, setBusy] = useState(false);
    const [deleteBusy, setDeleteBusy] = useState(false);
    const [deleteTarget, setDeleteTarget] = useState<Credential | null>(null);
    const [exportBusy, setExportBusy] = useState(false);
    const [importBusy, setImportBusy] = useState(false);
    const [toast, setToast] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);
    const [avatarLoadError, setAvatarLoadError] = useState(false);
    const [profileDialogOpen, setProfileDialogOpen] = useState(false);
    const [avatarPreview, setAvatarPreview] = useState<string | null>(null);
    const [avatarDialogError, setAvatarDialogError] = useState<string | null>(null);
    const [avatarSaving, setAvatarSaving] = useState(false);
    const [mfaStatus, setMfaStatus] = useState<MfaStatusResponse | null>(null);
    const [mfaLoading, setMfaLoading] = useState(false);
    const [mfaActionBusy, setMfaActionBusy] = useState(false);
    const [mfaEnrollment, setMfaEnrollment] = useState<MfaEnrollmentResponse | null>(null);
    const [mfaCodeInput, setMfaCodeInput] = useState('');
    const [mfaDisableCode, setMfaDisableCode] = useState('');
    const [mfaDisableRecoveryCode, setMfaDisableRecoveryCode] = useState('');
    const [mfaMessage, setMfaMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
    const [passkeySupported, setPasskeySupported] = useState(() => isWebAuthnSupported());
    const [passkeyBusy, setPasskeyBusy] = useState(false);
    const [passkeyMessage, setPasskeyMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedCategory, setSelectedCategory] = useState<string>(ALL_CATEGORY_ID);

    const [rotateCurrentPassword, setRotateCurrentPassword] = useState('');
    const [rotateNewPassword, setRotateNewPassword] = useState('');
    const [rotateConfirmPassword, setRotateConfirmPassword] = useState('');
    const [rotateInvalidateSessions, setRotateInvalidateSessions] = useState(false);
    const [rotateBusy, setRotateBusy] = useState(false);
    const [rotateMessage, setRotateMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
    const [revokeBusy, setRevokeBusy] = useState(false);

    const [migrating, setMigrating] = useState(false);

    const [totpCode, setTotpCode] = useState<string | null>(null);
    const [totpProgress, setTotpProgress] = useState(0);

    const fileInputRef = useRef<HTMLInputElement | null>(null);

    const isAuditAdmin = useMemo(() => isAuditAdminEmail(user?.email ?? null), [user?.email]);

    const avatarInitials = useMemo(() => {
        const preferred = user?.username || user?.email || '';
        if (!preferred) return 'U';
        const identifier = preferred.includes('@') ? preferred.split('@')[0] ?? preferred : preferred;
        const sanitized = identifier.trim();
        if (!sanitized) {
            return (user?.email || user?.username || 'U').slice(0, 2).toUpperCase();
        }
        const segments = sanitized.split(/[.\-_\s]/).filter(Boolean);
        if (segments.length === 0) {
            return sanitized.slice(0, 2).toUpperCase();
        }
        if (segments.length === 1) {
            return segments[0].slice(0, 2).toUpperCase();
        }
        return `${segments[0][0] ?? ''}${segments[segments.length - 1][0] ?? ''}`.toUpperCase();
    }, [user?.email, user?.username]);

    const avatarSrc = user?.avatarData ?? null;
    const avatarChanged = avatarPreview !== avatarSrc;

    const pwdStrength = useMemo(
        () =>
            assessPasswordStrength(password, [username, title, user?.email ?? '', user?.username ?? '']),
        [password, title, user?.email, user?.username, username]
    );

    const unlockDialogTitle = useMemo(() => {
        if (pendingDialogMode === 'edit') {
            return 'Unlock Vault to Edit Credential';
        }
        if (pendingDialogMode === 'add') {
            return 'Unlock Vault to Add Credential';
        }
        return 'Unlock vault';
    }, [pendingDialogMode]);

    const unlockDialogDescription = useMemo(() => {
        if (pendingDialogMode === 'edit') {
            return 'Your vault is locked. Enter your master password to edit this credential.';
        }
        if (pendingDialogMode === 'add') {
            return 'Your vault is locked. Enter your master password to add a new credential.';
        }
        return 'Enter your master password to decrypt your vault and view credentials.';
    }, [pendingDialogMode]);
    useEffect(() => {
        setPasskeySupported(isWebAuthnSupported());
    }, []);

    const promptUnlock = useCallback((mode: 'add' | 'edit' | null, target: Credential | null = null) => {
        setPendingDialogMode(mode);
        setPendingEditTarget(target);
        setUnlockPassword('');
        setUnlockError(null);
        setShowUnlockPwd(false);
        setShowUnlockDialog(true);
    }, []);

    useEffect(() => {
        if (!user?.id) {
            restoreAttemptedRef.current = null;
            return;
        }
        if (!locked || dek || restoreAttemptedRef.current === user.id) {
            return;
        }
        restoreAttemptedRef.current = user.id;
        void (async () => {
            const remembered = await restoreDek(user.id);
            if (remembered) {
                setDEK(remembered);
            }
        })();
    }, [user?.id, locked, dek, setDEK]);

    useEffect(() => {
        if (locked && !hadDek && !autoPromptedUnlock) {
            promptUnlock(null);
            setAutoPromptedUnlock(true);
        }
    }, [locked, hadDek, autoPromptedUnlock, promptUnlock]);
    const pwdScore = pwdStrength.score;
    const pwdProgress = (pwdScore / 4) * 100;
    const strengthLabel = password ? getPasswordStrengthLabel(pwdScore) : 'No password entered';
    const strengthSuggestions = password
        ? pwdStrength.suggestions
        : [
            'Use a long, unique password to improve security.',
            'Avoid reusing passwords between different websites.',
        ];
    const strengthColor = getPasswordStrengthColor(pwdScore);
    const passwordTooWeak =
        Boolean(password) && (pwdStrength.compromised || pwdStrength.score < MIN_ACCEPTABLE_PASSWORD_SCORE);
    const passwordWarning = !password
        ? null
        : pwdStrength.compromised
            ? 'This password was found in known breaches. Choose a different one before saving.'
            : pwdStrength.score < MIN_ACCEPTABLE_PASSWORD_SCORE
                ? 'This password is too weak. Increase its length and complexity before saving.'
                : null;
    const saveDisabled = busy || !title.trim() || !username.trim() || !password;
    const rotateDisabled =
        rotateBusy
        || locked
        || !dek
        || !user
        || !rotateCurrentPassword.trim()
        || !rotateNewPassword.trim()
        || rotateNewPassword !== rotateConfirmPassword;

    useEffect(() => {
        if (!locked && dek) return;

        setCredentials([]);
        setSelected(null);
        setDialogMode(null);
        setEditingTarget(null);
        setPendingDialogMode(null);
        setPendingEditTarget(null);
        setUnlockPassword('');
        setUnlockError(null);
        setShowUnlockPwd(false);
        setTitle('');
        setUsername('');
        setPassword('');
        setUrl('');
        setNotes('');
        setTags('');
        setTotpSecret('');
        setShowPwd(false);
        setBusy(false);
        setDeleteBusy(false);
        setDeleteTarget(null);
        setSearchQuery('');
        setSelectedCategory(ALL_CATEGORY_ID);
        setRotateCurrentPassword('');
        setRotateNewPassword('');
        setRotateConfirmPassword('');
        setRotateInvalidateSessions(false);
        setRotateMessage(null);
        setFavoriteBusy(false);
    }, [dek, locked]);

    useEffect(() => {
        if (!dek) return;
        if (!user) return;

        (async () => {
            try {
                const legacyResponse = await api.fetchCredentials();
                const legacyCreds = legacyResponse.credentials;

                if (legacyCreds.length > 0) {
                    setMigrating(true);
                    setToast({type: 'success', msg: `Migrating ${legacyCreds.length} legacy items to new Vault format...`});

                    for (const old of legacyCreds) {
                        try {
                            const inferredTag = inferCategoryFromLegacy(old.service, old.websiteLink);

                            const {cipher: titleCipher, nonce: titleNonce} = await encryptField(dek, old.service);

                            await api.createVault({
                                titleCipher,
                                titleNonce,
                                usernameCipher: old.usernameEncrypted,
                                usernameNonce: old.usernameNonce,
                                passwordCipher: old.passwordEncrypted,
                                passwordNonce: old.passwordNonce,
                                url: old.websiteLink || undefined,
                                favorite: old.favorite,
                                collections: [inferredTag]
                            });

                            await api.deleteCredential(old.credentialId);
                        } catch (err) {
                            console.error("Migration failed for item", old.credentialId, err);
                        }
                    }
                    setToast({type: 'success', msg: 'Migration complete.'});
                    setMigrating(false);
                }

                const vaultItems: VaultItem[] = await api.listVault();
                const decrypted: Credential[] = [];

                for (const item of vaultItems) {
                    const titleDec = await decryptField(dek, item.titleCipher, item.titleNonce);
                    const usernameDec = await decryptField(dek, item.usernameCipher, item.usernameNonce);
                    const passwordDec = await decryptField(dek, item.passwordCipher, item.passwordNonce);
                    const notesDec = (item.notesCipher && item.notesNonce)
                        ? await decryptField(dek, item.notesCipher, item.notesNonce)
                        : '';
                    const totpDec = (item.totpCipher && item.totpNonce)
                        ? await decryptField(dek, item.totpCipher, item.totpNonce)
                        : '';

                    decrypted.push({
                        id: item.id!,
                        name: titleDec,
                        url: item.url,
                        username: usernameDec,
                        password: passwordDec,
                        notes: notesDec,
                        totpSecret: totpDec,
                        favorite: !!item.favorite,
                        collections: item.collections || []
                    });
                }

                setCredentials(decrypted);
                setSelected(decrypted[0] ?? null);
            } catch (err: unknown) {
                const message = err instanceof Error ? err.message : 'Failed to load vault';
                setToast({type: 'error', msg: message || 'Failed to load vault'});
                setMigrating(false);
            }
        })();
    }, [dek, user]);

    useEffect(() => {
        setAvatarLoadError(false);
    }, [user?.avatarData, user?.email]);

    useEffect(() => {
        setShowSelectedPassword(false);
    }, [selected?.id]);

    useEffect(() => {
        if (!selected?.totpSecret) {
            setTotpCode(null);
            setTotpProgress(0);
            return;
        }

        let totp: OTPAuth.TOTP | null = null;
        try {
            const secret = selected.totpSecret.replace(/\s+/g, '');
            totp = new OTPAuth.TOTP({
                secret: OTPAuth.Secret.fromBase32(secret),
                algorithm: 'SHA1',
                digits: 6,
                period: 30
            });
        } catch (e) {
            console.error('Invalid TOTP secret', e);
            setTotpCode('Invalid Secret');
            return;
        }

        const update = () => {
            if (!totp) return;
            const code = totp.generate();
            setTotpCode(code);

            const epoch = Math.floor(Date.now() / 1000);
            const period = 30;
            const progress = ((epoch % period) / period) * 100;
            setTotpProgress(progress);
        };

        update();
        const interval = setInterval(update, 1000);
        return () => clearInterval(interval);
    }, [selected?.totpSecret]);

    useEffect(() => {
        if (!profileDialogOpen) {
            return;
        }
        if (!user) {
            setMfaStatus(null);
            setMfaLoading(false);
            return;
        }
        let cancelled = false;
        setMfaEnrollment(null);
        setMfaCodeInput('');
        setMfaDisableCode('');
        setMfaDisableRecoveryCode('');
        setMfaMessage(null);
        setMfaLoading(true);

        (async () => {
            try {
                const status = await api.mfaStatus();
                if (!cancelled) {
                    setMfaStatus(status);
                }
            } catch (error) {
                if (!cancelled) {
                    const message = error instanceof Error ? error.message : 'Failed to load MFA status';
                    setMfaMessage({type: 'error', text: message || 'Failed to load MFA status'});
                    setMfaStatus(null);
                }
            } finally {
                if (!cancelled) {
                    setMfaLoading(false);
                }
            }
        })();

        return () => {
            cancelled = true;
        };
    }, [profileDialogOpen, user]);

    const categoryItems = useMemo<CategoryItem[]>(() => {
        const counts = new Map<string, number>();
        for (const credential of credentials) {
            if (credential.collections && credential.collections.length > 0) {
                for (const col of credential.collections) {
                    counts.set(col, (counts.get(col) ?? 0) + 1);
                }
            } else {
                counts.set(UNCATEGORIZED_LABEL, (counts.get(UNCATEGORIZED_LABEL) ?? 0) + 1);
            }
        }

        const dynamic = Array.from(counts.entries())
            .sort((a, b) => a[0].localeCompare(b[0], undefined, {sensitivity: 'base'}))
            .map<CategoryItem>(([label, count]) => ({
                id: label,
                label,
                count,
            }));

        return [
            {id: ALL_CATEGORY_ID, label: 'All Items', count: credentials.length},
            ...dynamic,
        ];
    }, [credentials]);

    useEffect(() => {
        if (selectedCategory === ALL_CATEGORY_ID) return;
        if (!categoryItems.some((category) => category.id === selectedCategory)) {
            setSelectedCategory(ALL_CATEGORY_ID);
        }
    }, [categoryItems, selectedCategory]);

    const filteredCredentials = useMemo(() => {
        const normalizedQuery = searchQuery.trim().toLowerCase();

        return credentials.filter((credential) => {
            if (selectedCategory !== ALL_CATEGORY_ID) {
                if (selectedCategory === UNCATEGORIZED_LABEL) {
                    if (credential.collections && credential.collections.length > 0) return false;
                } else {
                    if (!credential.collections?.includes(selectedCategory)) {
                        return false;
                    }
                }
            }

            if (!normalizedQuery) {
                return true;
            }

            const haystack = [credential.name, credential.username, credential.url ?? '', credential.notes ?? ''];
            return haystack.some((value) => value.toLowerCase().includes(normalizedQuery));
        });
    }, [credentials, searchQuery, selectedCategory]);

    const activeCategory = useMemo(() =>
            categoryItems.find((category) => category.id === selectedCategory) ?? categoryItems[0],
        [categoryItems, selectedCategory]);

    useEffect(() => {
        if (selected) {
            const match = filteredCredentials.find((credential) => credential.id === selected.id);
            if (match) {
                if (match !== selected) {
                    setSelected(match);
                }
                return;
            }
        }

        const nextSelection = filteredCredentials[0] ?? null;
        if (nextSelection !== selected) {
            setSelected(nextSelection);
        }
    }, [filteredCredentials, selected]);

    const renderCategoryIcon = (categoryId: string) => {
        if (categoryId === ALL_CATEGORY_ID) {
            return <Key/>;
        }
        if (categoryId === UNCATEGORIZED_LABEL) {
            return <Note/>;
        }
        return <LinkIcon/>;
    };

    const resetFormFields = () => {
        setTitle('');
        setUsername('');
        setPassword('');
        setUrl('');
        setNotes('');
        setTags('');
        setTotpSecret('');
        setShowPwd(false);
    };

    const handleProfileDialogOpen = () => {
        setAvatarPreview(user?.avatarData ?? null);
        setAvatarDialogError(null);
        setProfileDialogOpen(true);
    };

    const handleProfileDialogClose = () => {
        if (avatarSaving) return;
        setProfileDialogOpen(false);
        setAvatarPreview(null);
        setAvatarDialogError(null);
        setMfaStatus(null);
        setMfaEnrollment(null);
        setMfaCodeInput('');
        setMfaDisableCode('');
        setMfaDisableRecoveryCode('');
        setMfaMessage(null);
        setMfaLoading(false);
        setMfaActionBusy(false);
        setPasskeyMessage(null);
        setPasskeyBusy(false);
    };

    const handleAvatarFileChange = (event: ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        event.target.value = '';
        if (!file) return;

        if (!ALLOWED_AVATAR_TYPES.includes(file.type)) {
            setAvatarDialogError('Only PNG, JPEG, or WebP images are supported.');
            return;
        }

        if (file.size > MAX_AVATAR_SIZE) {
            setAvatarDialogError('Avatar must be 256 KB or smaller.');
            return;
        }

        const reader = new FileReader();
        reader.onload = () => {
            setAvatarDialogError(null);
            setAvatarPreview(typeof reader.result === 'string' ? reader.result : null);
        };
        reader.onerror = () => {
            setAvatarDialogError('Failed to read image file.');
        };
        reader.readAsDataURL(file);
    };

    const handleAvatarRemove = () => {
        setAvatarPreview(null);
        setAvatarDialogError(null);
    };

    const handleAvatarSave = async () => {
        if (!avatarChanged) {
            handleProfileDialogClose();
            return;
        }

        setAvatarDialogError(null);
        setAvatarSaving(true);
        try {
            const updatedUser = await api.updateAvatar(avatarPreview ?? null);
            login(updatedUser);
            setAvatarLoadError(false);
            setToast({
                type: 'success',
                msg: avatarPreview ? 'Avatar updated successfully.' : 'Avatar removed.',
            });
            setProfileDialogOpen(false);
            setAvatarPreview(null);
        } catch (err: unknown) {
            const message = err instanceof Error ? err.message : 'Failed to update avatar';
            setAvatarDialogError(message || 'Failed to update avatar');
        } finally {
            setAvatarSaving(false);
        }
    };

    const handleRotateMasterPassword = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        setRotateMessage(null);

        if (!user) {
            setRotateMessage({type: 'error', text: 'User profile unavailable. Try refreshing the page.'});
            return;
        }
        if (!dek || locked) {
            setRotateMessage({type: 'error', text: 'Unlock your vault before rotating the master password.'});
            return;
        }

        const current = rotateCurrentPassword.trim();
        const next = rotateNewPassword.trim();
        const confirm = rotateConfirmPassword.trim();

        if (!current) {
            setRotateMessage({type: 'error', text: 'Enter your current master password.'});
            return;
        }
        if (!next) {
            setRotateMessage({type: 'error', text: 'Enter a new master password.'});
            return;
        }
        if (next !== confirm) {
            setRotateMessage({type: 'error', text: 'New master passwords do not match.'});
            return;
        }

        setRotateBusy(true);
        try {
            const currentVerifier = await makeVerifier(user.email, current, user.saltClient);
            const newSaltClient = toB64(crypto.getRandomValues(new Uint8Array(16)));
            const newVerifier = await makeVerifier(user.email, next, newSaltClient);
            const newKek = await deriveKEK(next, newSaltClient);
            const {dekEncrypted, dekNonce} = await encryptDekWithKek(dek, newKek);

            await api.rotateMasterPassword({
                currentVerifier,
                newVerifier,
                newSaltClient,
                newDekEncrypted: dekEncrypted,
                newDekNonce: dekNonce,
                invalidateSessions: rotateInvalidateSessions,
            });

            setRotateMessage({
                type: 'success',
                text: rotateInvalidateSessions
                    ? 'Master password rotated. Sessions were revoked; sign in again everywhere.'
                    : 'Master password rotated successfully.',
            });
            setRotateCurrentPassword('');
            setRotateNewPassword('');
            setRotateConfirmPassword('');
            setRotateInvalidateSessions(false);
            await refresh();
        } catch (error) {
            const message = messageFromError(error, 'Failed to rotate master password');
            setRotateMessage({type: 'error', text: message});
        } finally {
            setRotateBusy(false);
        }
    };

    const handleRevokeSessions = async () => {
        if (revokeBusy) return;
        const confirmed = typeof window === 'undefined'
            ? true
            : window.confirm('Revoke all sessions? You will need to sign in again on every device.');
        if (!confirmed) return;

        setRevokeBusy(true);
        try {
            await api.revokeSessions();
            setToast({
                type: 'success',
                msg: 'All sessions revoked. Please sign in again on this device and others.',
            });
            await refresh();
        } catch (error) {
            const message = messageFromError(error, 'Failed to revoke sessions');
            setToast({type: 'error', msg: message});
        } finally {
            setRevokeBusy(false);
        }
    };

    const messageFromError = (error: unknown, fallback: string) =>
        error instanceof Error ? error.message || fallback : fallback;

    const handleStartMfaEnrollment = async () => {
        setMfaMessage(null);
        setMfaActionBusy(true);
        try {
            const enrollment = await api.mfaEnroll();
            setMfaEnrollment(enrollment);
            setMfaStatus({
                enabled: false,
                enabledAt: null,
                recoveryCodesRemaining: enrollment.recoveryCodes.length,
            });
            setMfaCodeInput('');
            setMfaDisableCode('');
            setMfaDisableRecoveryCode('');
            setMfaMessage({
                type: 'success',
                text: 'Add the secret below to your authenticator, then enter the generated code to activate multi-factor authentication.',
            });
        } catch (error) {
            const message = messageFromError(error, 'Failed to start MFA enrollment');
            setMfaMessage({type: 'error', text: message});
        } finally {
            setMfaActionBusy(false);
        }
    };

    const handleActivateMfa = async () => {
        const code = mfaCodeInput.trim();
        if (!code) {
            setMfaMessage({
                type: 'error',
                text: 'Enter the code from your authenticator app to activate MFA.',
            });
            return;
        }
        setMfaMessage(null);
        setMfaActionBusy(true);
        try {
            const status = await api.mfaActivate(code);
            setMfaStatus(status);
            setMfaMessage({
                type: 'success',
                text: 'Multi-factor authentication is now enabled. Store your recovery codes in a safe place.',
            });
            setMfaCodeInput('');
            await refresh();
        } catch (error) {
            const message = messageFromError(error, 'Failed to activate MFA');
            setMfaMessage({type: 'error', text: message});
        } finally {
            setMfaActionBusy(false);
        }
    };

    const handleDisableMfa = async () => {
        const code = mfaDisableCode.trim();
        const recovery = mfaDisableRecoveryCode.trim();
        if (!code && !recovery) {
            setMfaMessage({
                type: 'error',
                text: 'Provide either an authenticator code or a recovery code to disable MFA.',
            });
            return;
        }
        setMfaMessage(null);
        setMfaActionBusy(true);
        try {
            const status = await api.mfaDisable({
                code: code || undefined,
                recoveryCode: recovery || undefined,
            });
            setMfaStatus(status);
            setMfaEnrollment(null);
            setMfaCodeInput('');
            setMfaDisableCode('');
            setMfaDisableRecoveryCode('');
            setMfaMessage({
                type: 'success',
                text: 'Multi-factor authentication has been disabled.',
            });
            await refresh();
        } catch (error) {
            const message = messageFromError(error, 'Failed to disable MFA');
            setMfaMessage({type: 'error', text: message});
        } finally {
            setMfaActionBusy(false);
        }
    };

    const handleRegisterPasskey = async () => {
        const supported = isWebAuthnSupported();
        setPasskeySupported(supported);
        if (!supported) {
            setPasskeyMessage({
                type: 'error',
                text: 'Passkeys are not supported in this browser. Try a different browser or device.',
            });
            return;
        }

        setPasskeyMessage(null);
        setPasskeyBusy(true);
        try {
            const options = await api.startPasskeyRegistration();
            const publicKey = decodeCreationOptions(options.publicKey);
            const credential = await navigator.credentials.create({publicKey});
            if (!credential) {
                setPasskeyMessage({
                    type: 'error',
                    text: 'Passkey registration was cancelled.',
                });
                return;
            }
            if (!(credential instanceof PublicKeyCredential)) {
                setPasskeyMessage({
                    type: 'error',
                    text: 'Unexpected credential type returned by the browser.',
                });
                return;
            }
            const attestation = attestationToJSON(credential);
            const result = await api.finishPasskeyRegistration({
                requestId: options.requestId,
                credential: attestation,
            });
            const responseMessage = result?.message?.trim();
            setPasskeyMessage({
                type: 'success',
                text: responseMessage || 'Passkey registered successfully.',
            });
        } catch (error) {
            if (error instanceof ApiError) {
                const {message} = extractApiErrorDetails(error);
                setPasskeyMessage({
                    type: 'error',
                    text: message || 'Failed to register a passkey.',
                });
            } else if (error instanceof DOMException) {
                if (error.name === 'NotAllowedError') {
                    setPasskeyMessage({
                        type: 'error',
                        text: 'Passkey registration was cancelled or timed out.',
                    });
                } else {
                    setPasskeyMessage({
                        type: 'error',
                        text: error.message || 'Passkey registration failed.',
                    });
                }
            } else {
                const message = error instanceof Error ? error.message : 'Failed to register a passkey.';
                setPasskeyMessage({
                    type: 'error',
                    text: message || 'Failed to register a passkey.',
                });
            }
        } finally {
            setPasskeyBusy(false);
        }
    };

    const renderRecoveryCodes = (codes: string[]) => (
        <Stack
            component="ul"
            spacing={0.5}
            sx={{listStyle: 'none', paddingLeft: 0, marginBottom: 0}}
        >
            {codes.map((code) => (
                <Typography
                    key={code}
                    component="li"
                    sx={{fontFamily: 'monospace', fontSize: 14}}
                >
                    {code}
                </Typography>
            ))}
        </Stack>
    );
    const openAddDialog = () => {
        resetFormFields();
        setDialogMode('add');
        setEditingTarget(null);
    };

    const openEditDialog = (credential: Credential) => {
        setDialogMode('edit');
        setEditingTarget(credential);
        setTitle(credential.name);
        setUsername(credential.username);
        setPassword(credential.password);
        setUrl(credential.url ?? '');
        setNotes(credential.notes ?? '');
        setTags(credential.collections.join(', '));
        setTotpSecret(credential.totpSecret ?? '');
        setShowPwd(false);
    };

    const handleDialogClose = () => {
        if (busy) return;
        setDialogMode(null);
        setEditingTarget(null);
        resetFormFields();
    };

    const handleAddClick = () => {
        if (!dek || locked) {
            promptUnlock('add');
            return;
        }
        openAddDialog();
    };

    const handleEditClick = () => {
        if (!selected) return;
        if (!dek || locked) {
            promptUnlock('edit', selected);
            return;
        }
        openEditDialog(selected);
    };

    const handleDeleteClick = () => {
        if (!selected) return;
        setDeleteTarget(selected);
    };

    const resetUnlockDialog = useCallback(() => {
        setShowUnlockDialog(false);
        setUnlockPassword('');
        setUnlockError(null);
        setShowUnlockPwd(false);
        setPendingDialogMode(null);
        setPendingEditTarget(null);
        setUnlockBusy(false);
    }, []);

    const closeUnlockDialog = useCallback(() => {
        if (unlockBusy) return;
        resetUnlockDialog();
    }, [resetUnlockDialog, unlockBusy]);

    const handleLogoutClick = useCallback(() => {
        resetUnlockDialog();
        void logout();
    }, [logout, resetUnlockDialog]);

    const handleUnlock = async () => {
        if (!unlockPassword || unlockBusy) return;
        setUnlockBusy(true);
        setUnlockError(null);

        const userProfile = user;
        if (!userProfile?.id) {
            setUnlockError('Master password invalid');
            setUnlockBusy(false);
            return;
        }

        try {
            const kek = await deriveKEK(unlockPassword, userProfile.saltClient);
            const dekKey = await unwrapDEK(kek, userProfile.dekEncrypted, userProfile.dekNonce);
            await rememberDek(userProfile.id, dekKey);
            setDEK(dekKey);
            const nextMode = pendingDialogMode;
            const nextEditTarget = pendingEditTarget;
            resetUnlockDialog();
            if (nextMode === 'add') {
                openAddDialog();
            } else if (nextMode === 'edit' && nextEditTarget) {
                openEditDialog(nextEditTarget);
            }
        } catch {
            setUnlockError('Master password invalid');
        } finally {
            setUnlockBusy(false);
        }
    };

    async function handleSave() {
        if (!dek || !dialogMode) {
            setToast({type: 'error', msg: 'Session not ready. Unlock vault and try again.'});
            return;
        }

        setBusy(true);
        try {
            const {cipher: usernameCipher, nonce: usernameNonce} = await encryptField(dek, username);
            const {cipher: passwordCipher, nonce: passwordNonce} = await encryptField(dek, password);
            const {cipher: titleCipher, nonce: titleNonce} = await encryptField(dek, title);
            const {cipher: notesCipher, nonce: notesNonce} = await encryptField(dek, notes);
            const {cipher: totpCipher, nonce: totpNonce} = await encryptField(dek, totpSecret);

            const trimmedTitle = title.trim();
            const trimmedUrl = url.trim();
            const trimmedUsername = username.trim();
            const collectionList = tags.split(',').map(t => t.trim()).filter(Boolean);

            if (dialogMode === 'add') {
                const created = await api.createVault({
                    titleCipher,
                    titleNonce,
                    usernameCipher,
                    usernameNonce,
                    passwordCipher,
                    passwordNonce,
                    url: trimmedUrl,
                    notesCipher,
                    notesNonce,
                    totpCipher,
                    totpNonce,
                    collections: collectionList
                });

                const newCredential: Credential = {
                    id: created.id!,
                    name: trimmedTitle,
                    url: trimmedUrl || undefined,
                    username: trimmedUsername,
                    password: password,
                    notes: notes,
                    totpSecret: totpSecret,
                    favorite: !!created.favorite,
                    collections: created.collections || [],
                };

                setCredentials((prev) => [newCredential, ...prev]);
                setSelected(newCredential);
                setToast({type: 'success', msg: 'Item saved.'});
            } else if (dialogMode === 'edit' && editingTarget) {
                const updated = await api.updateVault(editingTarget.id, {
                    titleCipher,
                    titleNonce,
                    usernameCipher,
                    usernameNonce,
                    passwordCipher,
                    passwordNonce,
                    url: trimmedUrl,
                    notesCipher,
                    notesNonce,
                    totpCipher,
                    totpNonce,
                    collections: collectionList
                });

                const updatedCredential: Credential = {
                    id: editingTarget.id,
                    name: trimmedTitle,
                    url: trimmedUrl || undefined,
                    username: trimmedUsername,
                    password: password,
                    notes: notes,
                    totpSecret: totpSecret,
                    favorite: !!updated.favorite,
                    collections: updated.collections || []
                };

                setCredentials((prev) =>
                    prev.map((cred) => (cred.id === editingTarget.id ? updatedCredential : cred)),
                );
                setSelected((prevSelected) =>
                    prevSelected && prevSelected.id === editingTarget.id ? updatedCredential : prevSelected,
                );
                setToast({type: 'success', msg: 'Item updated.'});
            }

            setDialogMode(null);
            setEditingTarget(null);
            setPendingDialogMode(null);
            setPendingEditTarget(null);
            resetFormFields();
        } catch (e: unknown) {
            const message = e instanceof Error ? e.message : 'Failed to save';
            setToast({type: 'error', msg: message || 'Failed to save'});
        } finally {
            setBusy(false);
        }
    }

    const handleDeleteConfirm = async () => {
        if (!deleteTarget) return;
        setDeleteBusy(true);
        try {
            await api.deleteVault(deleteTarget.id);
            setCredentials((prev) => {
                const next = prev.filter((cred) => cred.id !== deleteTarget.id);
                if (selected?.id === deleteTarget.id) {
                    setSelected(next[0] ?? null);
                }
                return next;
            });
            setToast({type: 'success', msg: 'Item deleted.'});
            setDeleteTarget(null);
        } catch (e: unknown) {
            const message = e instanceof Error ? e.message : 'Failed to delete item';
            setToast({type: 'error', msg: message || 'Failed to delete item'});
        } finally {
            setDeleteBusy(false);
        }
    };

    const handleDeleteDialogClose = () => {
        if (deleteBusy) return;
        setDeleteTarget(null);
    };

    const handleExportVault = async () => {
        if (!dek) {
            setToast({type: 'error', msg: 'Unlock your vault to export credentials.'});
            return;
        }
        if (exportBusy) return;

        setExportBusy(true);
        try {
            const payload = await serializeVaultCredentials(dek, credentials);
            const blob = new Blob([payload], {type: 'application/json'});
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const filename = `vault-${timestamp}.pmvault`;

            if (typeof window === 'undefined') {
                setToast({type: 'error', msg: 'Export is not available in this environment.'});
                return;
            }

            const urlObject = window.URL.createObjectURL(blob);
            const anchor = document.createElement('a');
            anchor.href = urlObject;
            anchor.download = filename;
            anchor.style.display = 'none';
            document.body.appendChild(anchor);
            anchor.click();
            document.body.removeChild(anchor);
            window.URL.revokeObjectURL(urlObject);

            const count = credentials.length;
            setToast({
                type: 'success',
                msg: count === 0
                    ? 'Exported an empty vault file.'
                    : `Vault exported with ${count} item${count === 1 ? '' : 's'}.`,
            });
        } catch (error: unknown) {
            const message = error instanceof Error ? error.message : 'Failed to export vault.';
            setToast({type: 'error', msg: message || 'Failed to export vault.'});
        } finally {
            setExportBusy(false);
        }
    };

    const handleImportClick = () => {
        if (!dek) {
            setToast({type: 'error', msg: 'Unlock your vault to import credentials.'});
            return;
        }
        if (importBusy) return;
        fileInputRef.current?.click();
    };

    const handleImportFileChange = async (event: ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        event.target.value = '';
        if (!file) return;
        if (!dek) {
            setToast({type: 'error', msg: 'Unlock your vault to import credentials.'});
            return;
        }

        setImportBusy(true);
        try {
            const raw = await file.text();
            const imported = await deserializeVaultCredentials(dek, raw);
            if (imported.length === 0) {
                setToast({type: 'success', msg: 'Vault file contained no items.'});
                return;
            }

            let nextCredentials = [...credentials];
            let nextSelected = selected;
            let updatedCount = 0;
            let createdCount = 0;

            for (const cred of imported) {
                const trimmedTitle = cred.name.trim();
                const sanitizedTitle = trimmedTitle || cred.name;
                const trimmedUrl = cred.url?.trim();
                const sanitizedUrl = trimmedUrl && trimmedUrl.length > 0 ? trimmedUrl : undefined;
                const trimmedUsername = cred.username.trim();
                const sanitizedUsername = trimmedUsername || cred.username;
                const tags = cred.collections || [];

                const {cipher: usernameCipher, nonce: usernameNonce} = await encryptField(dek, sanitizedUsername);
                const {cipher: passwordCipher, nonce: passwordNonce} = await encryptField(dek, cred.password);
                const {cipher: titleCipher, nonce: titleNonce} = await encryptField(dek, sanitizedTitle);

                const existingIndex = nextCredentials.findIndex((c) => c.name === sanitizedTitle && c.username === sanitizedUsername);

                if (existingIndex >= 0) {
                    const existingId = nextCredentials[existingIndex].id;
                    const updated = await api.updateVault(existingId, {
                        titleCipher,
                        titleNonce,
                        usernameCipher,
                        usernameNonce,
                        passwordCipher,
                        passwordNonce,
                        url: sanitizedUrl,
                        collections: tags,
                    });

                    const updatedCredential: Credential = {
                        id: existingId,
                        name: sanitizedTitle,
                        url: sanitizedUrl,
                        username: sanitizedUsername,
                        password: cred.password,
                        notes: nextCredentials[existingIndex].notes,
                        totpSecret: nextCredentials[existingIndex].totpSecret,
                        favorite: !!updated.favorite,
                        collections: updated.collections || []
                    };

                    nextCredentials[existingIndex] = updatedCredential;
                    if (nextSelected?.id === existingId) {
                        nextSelected = updatedCredential;
                    }
                    updatedCount++;
                } else {
                    const created = await api.createVault({
                        titleCipher,
                        titleNonce,
                        usernameCipher,
                        usernameNonce,
                        passwordCipher,
                        passwordNonce,
                        url: sanitizedUrl,
                        collections: tags
                    });

                    const newCredential: Credential = {
                        id: created.id!,
                        name: sanitizedTitle,
                        url: sanitizedUrl,
                        username: sanitizedUsername,
                        password: cred.password,
                        notes: '',
                        totpSecret: '',
                        favorite: !!created.favorite,
                        collections: created.collections || []
                    };

                    nextCredentials = [...nextCredentials, newCredential];
                    if (!nextSelected) {
                        nextSelected = newCredential;
                    }
                    createdCount++;
                }
            }

            setCredentials(nextCredentials);
            setSelected((prevSelected) => {
                if (nextSelected) return nextSelected;
                return nextCredentials[0] ?? null;
            });

            const total = imported.length;
            setToast({
                type: 'success',
                msg: `Imported ${total} item${total === 1 ? '' : 's'} (${updatedCount} updated, ${createdCount} created).`,
            });
        } catch (error: unknown) {
            let message = 'Failed to import vault.';
            if (error instanceof DOMException) {
                message = 'Unable to decrypt vault file with the current key.';
            } else if (error instanceof Error) {
                message = error.message || message;
            }
            setToast({type: 'error', msg: message});
        } finally {
            setImportBusy(false);
        }
    };

    const selectedIsFavorite = selected?.favorite ?? false;

    const handleToggleFavorite = async () => {
        if (!selected || favoriteBusy) return;

        const targetId = selected.id;
        const nextFavorite = !selected.favorite;
        setFavoriteBusy(true);
        try {
            const updated = await api.updateVaultMetadata(targetId, { favorite: nextFavorite });
            setCredentials((prev) =>
                prev.map((cred) =>
                    cred.id === targetId
                        ? {
                            ...cred,
                            favorite: !!updated.favorite,
                        }
                        : cred,
                ),
            );
            setSelected((prevSelected) =>
                prevSelected && prevSelected.id === targetId
                    ? {...prevSelected, favorite: !!updated.favorite}
                    : prevSelected,
            );
        } catch (error) {
            const message = messageFromError(error, 'Failed to update favorite');
            setToast({type: 'error', msg: message});
        } finally {
            setFavoriteBusy(false);
        }
    };

    const handleCopyPassword = async () => {
        if (!selected?.password) return;
        if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
            setToast({
                type: 'error',
                msg: 'Copying passwords is not supported in this browser.',
            });
            return;
        }

        try {
            await navigator.clipboard.writeText(selected.password);
            setToast({type: 'success', msg: 'Password copied to clipboard.'});
        } catch (error) {
            console.error('Failed to copy password.', error);
            setToast({type: 'error', msg: 'Failed to copy password.'});
        }
    };

    const handleCopyTotp = async () => {
        if (!totpCode) return;
        if (!navigator.clipboard || typeof navigator.clipboard.writeText !== 'function') {
            setToast({
                type: 'error',
                msg: 'Copying code is not supported in this browser.',
            });
            return;
        }

        try {
            await navigator.clipboard.writeText(totpCode);
            setToast({type: 'success', msg: 'Code copied to clipboard.'});
        } catch (error) {
            setToast({type: 'error', msg: 'Failed to copy code.'});
        }
    };

    const handleGeneratorMenuClose = () => {
        setGeneratorAnchorEl(null);
    };

    const handleGeneratorMenuOpen = (event: MouseEvent<HTMLButtonElement>) => {
        setGeneratorAnchorEl(event.currentTarget);
    };

    const handleSelectTemplate = (templateId: string) => {
        const template = passwordTemplates.find((item) => item.id === templateId);
        if (template) {
            setPassword(template.generate());
            setShowPwd(true);
        }
        handleGeneratorMenuClose();
    };

    const drawerContent = (
        <>
            <Box p={2}>
                <Typography variant="h6" fontWeight={700} gutterBottom>
                    {activeCategory
                        ? `${activeCategory.label} (${activeCategory.count})`
                        : `All Items (${credentials.length})`}
                </Typography>
            </Box>
            <Divider/>
            <List dense>
                {categoryItems.map((category) => (
                    <ListItemButton
                        key={category.id}
                        selected={selectedCategory === category.id}
                        onClick={() => {
                            setSelectedCategory(category.id);
                            if (isMobile) setMobileOpen(false);
                        }}
                    >
                        <ListItemIcon sx={{minWidth: 36}}>{renderCategoryIcon(category.id)}</ListItemIcon>
                        <ListItemText primary={`${category.label} (${category.count})`}/>
                    </ListItemButton>
                ))}
                {isAuditAdmin && (
                    <>
                        <Divider sx={{my: 1}}/>
                        <ListItemButton onClick={() => {
                            navigate('/audit-log');
                            if (isMobile) setMobileOpen(false);
                        }}>
                            <ListItemIcon sx={{minWidth: 36}}><ListAlt/></ListItemIcon>
                            <ListItemText primary="Audit Log"/>
                        </ListItemButton>
                    </>
                )}
            </List>
        </>
    );

    return (
        <Box display="flex" minHeight="100vh" sx={{bgcolor: 'background.default'}}>
            <input
                ref={fileInputRef}
                type="file"
                accept=".pmvault,application/json"
                hidden
                onChange={handleImportFileChange}
            />
            <Drawer
                variant="temporary"
                open={mobileOpen}
                onClose={handleDrawerToggle}
                ModalProps={{keepMounted: true}}
                sx={{
                    display: {xs: 'block', md: 'none'},
                    '& .MuiDrawer-paper': {boxSizing: 'border-box', width: 260},
                }}
            >
                {drawerContent}
            </Drawer>

            <Drawer
                variant="permanent"
                anchor="left"
                sx={{
                    display: {xs: 'none', md: 'block'},
                    '& .MuiDrawer-paper': {
                        width: 260,
                        borderRight: '1px solid',
                        borderColor: 'divider',
                        bgcolor: 'background.paper',
                        boxSizing: 'border-box',
                    },
                }}
                open
            >
                {drawerContent}
            </Drawer>

            <Box
                flex={1}
                p={3}
                component="main"
                sx={{
                    marginLeft: {xs: 0, md: '260px'},
                    width: {md: `calc(100% - 260px)`},
                    height: {md: '100vh'},
                    overflow: {md: 'hidden'},
                    display: {md: 'flex'},
                    flexDirection: {md: 'column'},
                }}
            >
                <Box display="flex" alignItems="center" justifyContent="space-between" marginBottom={2} gap={2}>
                    <Box display="flex" alignItems="center" gap={1} flex={1}>
                        {isMobile && (
                            <IconButton
                                color="inherit"
                                aria-label="open drawer"
                                edge="start"
                                onClick={handleDrawerToggle}
                                sx={{mr: 1}}
                            >
                                <MenuIcon/>
                            </IconButton>
                        )}
                        {(!isMobile || searchExpanded) && (
                            <TextField
                                placeholder="Search"
                                value={searchQuery}
                                onChange={(event) => setSearchQuery(event.target.value)}
                                size="small"
                                autoFocus={isMobile && searchExpanded}
                                onBlur={() => {
                                    if (isMobile && !searchQuery) setSearchExpanded(false);
                                }}
                                sx={{maxWidth: 420, width: isMobile ? '100%' : 'auto', flex: 1}}
                                slotProps={{
                                    input: {
                                        startAdornment: (
                                            <InputAdornment position="start">
                                                <Search fontSize="small"/>
                                            </InputAdornment>
                                        ),
                                    },
                                }}
                            />
                        )}
                        {isMobile && !searchExpanded && (
                            <IconButton onClick={() => setSearchExpanded(true)}>
                                <Search/>
                            </IconButton>
                        )}
                    </Box>

                    <Box display="flex" alignItems="center" gap={2}>

                        <IconButton onClick={handleUserMenuOpen} sx={{p: 0}}>
                            <Avatar
                                alt={user?.email ?? 'User'}
                                src={avatarLoadError ? undefined : avatarSrc ?? undefined}
                                slotProps={{img: {onError: () => setAvatarLoadError(true)}}}
                            >
                                {avatarInitials}
                            </Avatar>
                        </IconButton>
                        {!isMobile && (
                            <Typography variant="body2">{user?.email ?? 'No user email found'}</Typography>
                        )}
                        <Menu
                            anchorEl={userMenuAnchor}
                            open={userMenuOpen}
                            onClose={handleUserMenuClose}
                            onClick={handleUserMenuClose}
                            transformOrigin={{ horizontal: 'right', vertical: 'top' }}
                            anchorOrigin={{ horizontal: 'right', vertical: 'bottom' }}
                        >
                            <MenuItem disabled sx={{opacity: 1, color: 'text.primary', fontWeight: 600}}>
                                <Typography variant="body2">{user?.email ?? 'User'}</Typography>
                            </MenuItem>
                            <Divider/>
                            <MenuItem onClick={handleProfileDialogOpen}>
                                <ListItemIcon><Settings fontSize="small"/></ListItemIcon>
                                <ListItemText>Settings</ListItemText>
                            </MenuItem>
                            <MenuItem onClick={() => {
                                handleLogoutClick();
                            }}>
                                <ListItemIcon><Logout fontSize="small"/></ListItemIcon>
                                <ListItemText>Log out</ListItemText>
                            </MenuItem>
                        </Menu>
                    </Box>
                </Box>

                <Box
                    display="grid"
                    gridTemplateColumns={{xs: '1fr', md: '280px 1fr'}}
                    gap={2}
                    sx={{
                        flex: {md: 1},
                        minHeight: {md: 0},
                    }}
                >
                    <Card
                        variant="outlined"
                        sx={{
                            overflow: 'hidden',
                            height: {md: '100%'},
                            display: {md: 'flex'},
                            flexDirection: {md: 'column'},
                        }}
                    >
                        <List
                            dense
                            disablePadding
                            sx={{
                                overflowY: {md: 'auto'},
                                flex: {md: 1},
                            }}
                        >
                            {locked ? (
                                <ListItem>
                                    <ListItemText primary="Vault locked" secondary="Unlock to view items."/>
                                </ListItem>
                            ) : migrating ? (
                                <ListItem>
                                    <ListItemText primary="Migrating data..." secondary="Please wait."/>
                                    <CircularProgress size={20} sx={{ml: 2}}/>
                                </ListItem>
                            ) : filteredCredentials.length === 0 ? (
                                <ListItem>
                                    <ListItemText
                                        primary={
                                            searchQuery
                                                ? 'No items match your search.'
                                                : 'No items in this category yet.'
                                        }
                                    />
                                </ListItem>
                            ) : (
                                filteredCredentials.map((credential) => {
                                    const active = selected?.id === credential.id;
                                    return (
                                        <ListItemButton
                                            key={credential.id}
                                            selected={active}
                                            onClick={() => setSelected(credential)}
                                            sx={{
                                                '&.Mui-selected': {
                                                    bgcolor: 'action.selected',
                                                    borderLeft: '4px solid',
                                                    borderColor: 'primary.main'
                                                },
                                            }}
                                        >
                                            <ListItemText
                                                primary={
                                                    credential.favorite
                                                        ? `${credential.name} ★`
                                                        : credential.name
                                                }
                                                secondary={credential.username || '—'}
                                            />
                                        </ListItemButton>
                                    );
                                })
                            )}
                        </List>
                    </Card>

                    <Card
                        sx={{
                            minHeight: 420,
                            height: {md: '100%'},
                            overflowY: {md: 'auto'},
                        }}
                        elevation={0}
                        variant="outlined"
                    >
                        <CardContent>
                            {locked ? (
                                <Box
                                    display="flex"
                                    flexDirection="column"
                                    alignItems="center"
                                    justifyContent="center"
                                    minHeight={360}
                                    textAlign="center"
                                    gap={2}
                                >
                                    <Box display="flex" flexDirection="column" gap={0.5}>
                                        <Typography variant="h6" fontWeight={700}>Vault locked</Typography>
                                        <Typography variant="body2" color="text.secondary">
                                            Unlock your vault to view details.
                                        </Typography>
                                    </Box>
                                    <Button
                                        variant="contained"
                                        onClick={() => promptUnlock(null)}
                                        startIcon={<LockOpen/>}
                                        data-testid="unlock-vault-button"
                                        disableElevation
                                    >
                                        Unlock vault
                                    </Button>
                                </Box>
                            ) : (
                                <>
                                    <Box display="flex" justifyContent="space-between" alignItems="center" marginBottom={1.5}>
                                        <Typography variant="h6" fontWeight={700}>
                                            {selected?.name || 'Select an item'}
                                        </Typography>
                                        <Box>
                                            <IconButton
                                                size="small"
                                                onClick={handleAddClick}
                                                title="Add item"
                                            >
                                                <AddIcon/>
                                            </IconButton>
                                            <IconButton
                                                size="small"
                                                onClick={handleExportVault}
                                                title="Export vault"
                                                disabled={!dek || exportBusy}
                                            >
                                                <Download/>
                                            </IconButton>
                                            <IconButton
                                                size="small"
                                                onClick={handleImportClick}
                                                title="Import vault"
                                                disabled={!dek || importBusy}
                                            >
                                                <UploadFile/>
                                            </IconButton>
                                            <IconButton
                                                size="small"
                                                onClick={handleToggleFavorite}
                                                disabled={!selected || favoriteBusy}
                                                title={selectedIsFavorite ? 'Remove from favorites' : 'Add to favorites'}
                                            >
                                                {selectedIsFavorite ? <Star color="warning"/> : <StarBorder/>}
                                            </IconButton>
                                            <IconButton
                                                size="small"
                                                onClick={handleEditClick}
                                                disabled={!selected}
                                                title="Edit item"
                                            >
                                                <Edit/>
                                            </IconButton>
                                            <IconButton
                                                size="small"
                                                onClick={handleDeleteClick}
                                                disabled={!selected}
                                                title="Delete item"
                                                color="error"
                                            >
                                                <Delete/>
                                            </IconButton>
                                        </Box>
                                    </Box>

                                    <Typography variant="caption" color="text.secondary">username</Typography>
                                    <Typography sx={{marginBottom: 1}}>{selected?.username || '—'}</Typography>

                                    <Typography variant="caption" color="text.secondary">password</Typography>
                                    <Box display="flex" alignItems="center" gap={0.5} sx={{marginBottom: 1}}>
                                        <Typography
                                            sx={{
                                                fontFamily: 'monospace',
                                                wordBreak: 'break-all',
                                                marginBottom: 0,
                                            }}
                                            title={showSelectedPassword ? selected?.password : undefined}
                                        >
                                            {selected
                                                ? showSelectedPassword
                                                    ? selected.password
                                                    : '••••••••'
                                                : '—'}
                                        </Typography>
                                        <IconButton
                                            size="small"
                                            onClick={() => setShowSelectedPassword((prev) => !prev)}
                                            disabled={!selected}
                                            title={showSelectedPassword ? 'Hide password' : 'Show password'}
                                        >
                                            {showSelectedPassword ? <VisibilityOff fontSize="small"/> :
                                                <Visibility fontSize="small"/>}
                                        </IconButton>
                                        <IconButton
                                            size="small"
                                            onClick={() => {
                                                void handleCopyPassword();
                                            }}
                                            disabled={!selected}
                                            title="Copy password"
                                        >
                                            <ContentCopy fontSize="small"/>
                                        </IconButton>
                                    </Box>

                                    {selected?.totpSecret && (
                                        <>
                                            <Typography variant="caption" color="text.secondary">totp code</Typography>
                                            <Box display="flex" alignItems="center" gap={2} sx={{mb: 1}}>
                                                <Typography variant="h6" sx={{fontFamily: 'monospace', fontWeight: 700, letterSpacing: 2}}>
                                                    {totpCode || '...'}
                                                </Typography>
                                                <IconButton size="small" onClick={handleCopyTotp} title="Copy code">
                                                    <ContentCopy fontSize="small"/>
                                                </IconButton>
                                                <CircularProgress
                                                    variant="determinate"
                                                    value={100}
                                                    size={20}
                                                    thickness={10}
                                                    sx={{
                                                        color: 'action.hover',
                                                        position: 'absolute',
                                                        ml: '160px'
                                                    }}
                                                />
                                                <CircularProgress
                                                    variant="determinate"
                                                    value={100 - (totpProgress * 3.33)}
                                                    size={20}
                                                    thickness={10}
                                                    color={totpProgress > 80 ? "error" : "primary"}
                                                />
                                            </Box>
                                            <LinearProgress
                                                variant="determinate"
                                                value={100 - totpProgress}
                                                sx={{
                                                    width: 140,
                                                    mb: 2,
                                                    height: 4,
                                                    borderRadius: 2,
                                                    '& .MuiLinearProgress-bar': {
                                                        transition: 'none'
                                                    }
                                                }}
                                            />
                                        </>
                                    )}

                                    <Typography variant="caption" color="text.secondary">strength</Typography>
                                    <Box sx={{
                                        height: 8,
                                        width: 140,
                                        backgroundColor: 'action.hover',
                                        borderRadius: 4,
                                        marginTop: 0.5,
                                        marginBottom: 2,
                                    }}>
                                        <Box sx={{
                                            height: '100%',
                                            width: '40%',
                                            backgroundColor: 'success.main',
                                            borderRadius: 4
                                        }}/>
                                    </Box>

                                    <Typography variant="caption" color="text.secondary">website</Typography>
                                    <Box sx={{ mb: 2 }}>
                                        {selected?.url ? (
                                            <Button
                                                href={selected.url}
                                                target="_blank"
                                                rel="noreferrer"
                                                size="small"
                                                startIcon={<LinkIcon/>}
                                            >
                                                {(() => {
                                                    try {
                                                        return new URL(selected.url!).hostname;
                                                    } catch {
                                                        return selected.url;
                                                    }
                                                })()}
                                            </Button>
                                        ) : (
                                            <Typography variant="body2" color="text.secondary">—</Typography>
                                        )}
                                    </Box>

                                    {selected?.collections && selected.collections.length > 0 && (
                                        <>
                                            <Typography variant="caption" color="text.secondary">tags</Typography>
                                            <Box display="flex" gap={1} flexWrap="wrap" sx={{ mb: 2 }}>
                                                {selected.collections.map((tag) => (
                                                    <Chip key={tag} label={tag} size="small" />
                                                ))}
                                            </Box>
                                        </>
                                    )}

                                    {selected?.notes && (
                                        <>
                                            <Typography variant="caption" color="text.secondary">notes</Typography>
                                            <Card variant="outlined" sx={{ bgcolor: 'action.hover', mt: 0.5 }}>
                                                <CardContent sx={{ py: 1, '&:last-child': { pb: 1 } }}>
                                                    <Typography variant="body2" style={{ whiteSpace: 'pre-wrap' }}>
                                                        {selected.notes}
                                                    </Typography>
                                                </CardContent>
                                            </Card>
                                        </>
                                    )}
                                </>
                            )}
                        </CardContent>
                    </Card>
                </Box>
            </Box>

            {/* Profile Dialog... (unchanged) */}
            <Dialog
                open={profileDialogOpen}
                onClose={(_, reason) => {
                    if (avatarSaving && (reason === 'backdropClick' || reason === 'escapeKeyDown')) {
                        return;
                    }
                    handleProfileDialogClose();
                }}
                fullWidth
                maxWidth="xs"
                slotProps={{
                    backdrop: {sx: {backdropFilter: 'blur(8px)', backgroundColor: 'rgba(2,6,23,0.45)'}},
                    paper: {sx: {borderRadius: 4, backgroundImage: 'none'}},
                }}
            >
                {/* ... */}
                <DialogTitle sx={{fontWeight: 800}}>Profile settings</DialogTitle>
                <DialogContent>
                    <Stack spacing={2}>
                        <DialogContentText>
                            Upload a square PNG, JPEG, or WebP image up to 256 KB. We'll store it securely with your
                            account and fall back to your initials if the upload fails.
                        </DialogContentText>
                        {avatarDialogError ? <Alert severity="error">{avatarDialogError}</Alert> : null}
                        <Stack direction="row" spacing={2} alignItems="center">
                            <Avatar
                                alt={user?.email ?? user?.username ?? 'User avatar'}
                                src={avatarPreview ?? avatarSrc ?? undefined}
                                sx={{width: 80, height: 80, fontSize: 28}}
                            >
                                {avatarInitials}
                            </Avatar>
                            <Stack spacing={1}>
                                <Button
                                    component="label"
                                    variant="outlined"
                                    startIcon={<Upload fontSize="small"/>}
                                >
                                    Choose image
                                    <input
                                        type="file"
                                        hidden
                                        accept={ALLOWED_AVATAR_TYPES.join(',')}
                                        onChange={handleAvatarFileChange}
                                    />
                                </Button>
                                <Button
                                    onClick={handleAvatarRemove}
                                    disabled={!avatarPreview && !avatarSrc}
                                    color="inherit"
                                    startIcon={<DeleteOutline fontSize="small"/>}
                                >
                                    Remove avatar
                                </Button>
                            </Stack>
                        </Stack>
                        <Divider/>
                        <Stack spacing={3}>
                            <Stack spacing={1.5}>
                                <Box display="flex" alignItems="center" justifyContent="space-between">
                                    <Box>
                                        <Typography variant="h6" fontWeight={700}>Account security</Typography>
                                        <Typography variant="body2" color="text.secondary">
                                            Rotate your master password and manage active sessions.
                                        </Typography>
                                    </Box>
                                </Box>
                                {rotateMessage ? (
                                    <Alert severity={rotateMessage.type}>{rotateMessage.text}</Alert>
                                ) : null}
                                <Box component="form" onSubmit={handleRotateMasterPassword}>
                                    <Stack spacing={1.5}>
                                        <TextField
                                            label="Current master password"
                                            type="password"
                                            autoComplete="current-password"
                                            value={rotateCurrentPassword}
                                            onChange={(event) => {
                                                setRotateCurrentPassword(event.target.value);
                                                setRotateMessage(null);
                                            }}
                                            size="small"
                                            fullWidth
                                            disabled={rotateBusy}
                                        />
                                        <TextField
                                            label="New master password"
                                            type="password"
                                            autoComplete="new-password"
                                            value={rotateNewPassword}
                                            onChange={(event) => {
                                                setRotateNewPassword(event.target.value);
                                                setRotateMessage(null);
                                            }}
                                            size="small"
                                            fullWidth
                                            disabled={rotateBusy}
                                        />
                                        <TextField
                                            label="Confirm new master password"
                                            type="password"
                                            autoComplete="new-password"
                                            value={rotateConfirmPassword}
                                            onChange={(event) => {
                                                setRotateConfirmPassword(event.target.value);
                                                setRotateMessage(null);
                                            }}
                                            size="small"
                                            fullWidth
                                            disabled={rotateBusy}
                                            error={
                                                !!rotateConfirmPassword
                                                && rotateNewPassword !== rotateConfirmPassword
                                            }
                                            helperText={
                                                rotateConfirmPassword
                                                && rotateNewPassword !== rotateConfirmPassword
                                                    ? 'Passwords do not match.'
                                                    : undefined
                                            }
                                        />
                                        <FormControlLabel
                                            control={(
                                                <Checkbox
                                                    checked={rotateInvalidateSessions}
                                                    onChange={(event) => setRotateInvalidateSessions(event.target.checked)}
                                                    disabled={rotateBusy}
                                                />
                                            )}
                                            label="Revoke other sessions after rotation"
                                        />
                                        <Button
                                            type="submit"
                                            variant="contained"
                                            disabled={rotateDisabled}
                                        >
                                            {rotateBusy ? 'Rotating…' : 'Rotate master password'}
                                        </Button>
                                    </Stack>
                                </Box>
                                <Typography variant="caption" color="text.secondary">
                                    Last rotated:{' '}
                                    {user?.masterPasswordLastRotated
                                        ? new Date(user.masterPasswordLastRotated).toLocaleString()
                                        : 'Never'}
                                </Typography>
                                <Stack spacing={1}>
                                    <Typography variant="subtitle2" fontWeight={600}>Active sessions</Typography>
                                    <Typography variant="body2" color="text.secondary">
                                        Revoking all sessions signs you out everywhere and requires signing in again.
                                    </Typography>
                                    <Button
                                        onClick={handleRevokeSessions}
                                        variant="outlined"
                                        color="error"
                                        disabled={revokeBusy}
                                    >
                                        {revokeBusy ? 'Revoking…' : 'Revoke all sessions'}
                                    </Button>
                                </Stack>
                            </Stack>
                            <Divider/>
                            <Stack spacing={1.5}>
                                <Box display="flex" alignItems="center" justifyContent="space-between">
                                    <Box>
                                        <Typography variant="h6" fontWeight={700}>Multi-factor
                                            authentication</Typography>
                                        <Typography variant="body2" color="text.secondary">
                                            Manage multi-factor authentication for your account.
                                        </Typography>
                                    </Box>
                                    <Chip
                                        label={
                                            mfaLoading
                                                ? 'Loading…'
                                                : mfaStatus
                                                    ? mfaStatus.enabled
                                                        ? 'MFA enabled'
                                                        : 'MFA disabled'
                                                    : 'Status unavailable'
                                        }
                                        color={
                                            mfaStatus
                                                ? mfaStatus.enabled
                                                    ? 'success'
                                                    : 'default'
                                                : mfaLoading
                                                    ? 'default'
                                                    : 'warning'
                                        }
                                        variant={mfaStatus?.enabled ? 'filled' : 'outlined'}
                                        size="small"
                                    />
                                </Box>
                                {mfaMessage ? (
                                    <Alert
                                        severity={mfaMessage.type}
                                        onClose={() => setMfaMessage(null)}
                                    >
                                        {mfaMessage.text}
                                    </Alert>
                                ) : null}
                                {mfaLoading ? (
                                    <LinearProgress/>
                                ) : mfaStatus?.enabled ? (
                                    <Stack spacing={1.5}>
                                        <Typography variant="body2">
                                            Multi-factor authentication is active
                                            {mfaStatus.enabledAt
                                                ? ` since ${new Date(mfaStatus.enabledAt).toLocaleString()}`
                                                : ''}.
                                        </Typography>
                                        <Typography variant="body2">
                                            Recovery codes remaining: {mfaStatus.recoveryCodesRemaining}
                                        </Typography>
                                        {mfaEnrollment?.recoveryCodes?.length ? (
                                            <>
                                                <Alert severity="info">
                                                    Save the recovery codes shown below. They were generated during your
                                                    most recent
                                                    enrollment and will not be displayed again.
                                                </Alert>
                                                {renderRecoveryCodes(mfaEnrollment.recoveryCodes)}
                                            </>
                                        ) : null}
                                        <Typography variant="body2">
                                            To disable MFA, provide a current authenticator code or one of your recovery
                                            codes.
                                        </Typography>
                                        <TextField
                                            label="Authenticator code"
                                            value={mfaDisableCode}
                                            onChange={(e) => setMfaDisableCode(e.target.value)}
                                            size="small"
                                            fullWidth
                                            autoComplete="one-time-code"
                                            disabled={mfaActionBusy}
                                        />
                                        <TextField
                                            label="Recovery code"
                                            helperText="Optional — use this if you no longer have access to your authenticator."
                                            value={mfaDisableRecoveryCode}
                                            onChange={(e) => setMfaDisableRecoveryCode(e.target.value)}
                                            size="small"
                                            fullWidth
                                            disabled={mfaActionBusy}
                                        />
                                        <Box display="flex" justifyContent="flex-end" gap={1}>
                                            <Button
                                                onClick={() => {
                                                    setMfaDisableCode('');
                                                    setMfaDisableRecoveryCode('');
                                                }}
                                                disabled={mfaActionBusy || (!mfaDisableCode && !mfaDisableRecoveryCode)}
                                            >
                                                Clear
                                            </Button>
                                            <Button
                                                onClick={() => {
                                                    void handleDisableMfa();
                                                }}
                                                variant="outlined"
                                                color="error"
                                                disabled={
                                                    mfaActionBusy
                                                    || (!mfaDisableCode.trim() && !mfaDisableRecoveryCode.trim())
                                                }
                                            >
                                                {mfaActionBusy ? 'Disabling…' : 'Disable MFA'}
                                            </Button>
                                        </Box>
                                    </Stack>
                                ) : (
                                    <Stack spacing={1.5}>
                                        <Typography variant="body2">
                                            Protect your account with an extra verification step. Start enrollment to
                                            generate
                                            an authenticator secret and recovery codes.
                                        </Typography>
                                        {mfaEnrollment ? (
                                            <Stack spacing={1.5}>
                                                <TextField
                                                    label="Authenticator secret"
                                                    value={mfaEnrollment.secret}
                                                    fullWidth
                                                    size="small"
                                                    slotProps={{input: {readOnly: true}}}
                                                />
                                                <TextField
                                                    label="otpauth URL"
                                                    value={mfaEnrollment.otpauthUrl}
                                                    fullWidth
                                                    size="small"
                                                    slotProps={{input: {readOnly: true}}}
                                                    multiline
                                                    minRows={2}
                                                />
                                                <Alert severity="info">
                                                    Save these recovery codes somewhere safe. They are only shown once.
                                                </Alert>
                                                {renderRecoveryCodes(mfaEnrollment.recoveryCodes)}
                                                <TextField
                                                    label="Authenticator code"
                                                    value={mfaCodeInput}
                                                    onChange={(e) => setMfaCodeInput(e.target.value)}
                                                    size="small"
                                                    fullWidth
                                                    autoComplete="one-time-code"
                                                    disabled={mfaActionBusy}
                                                />
                                                <Button
                                                    onClick={() => {
                                                        void handleActivateMfa();
                                                    }}
                                                    variant="contained"
                                                    disabled={mfaActionBusy || !mfaCodeInput.trim()}
                                                >
                                                    {mfaActionBusy ? 'Activating…' : 'Activate MFA'}
                                                </Button>
                                            </Stack>
                                        ) : (
                                            <Button
                                                onClick={() => {
                                                    void handleStartMfaEnrollment();
                                                }}
                                                variant="contained"
                                                disabled={mfaActionBusy}
                                            >
                                                {mfaActionBusy ? 'Starting…' : 'Enable MFA'}
                                            </Button>
                                        )}
                                    </Stack>
                                )}
                            </Stack>
                            <Divider/>
                            <Stack spacing={1.5}>
                                <Box display="flex" alignItems="center" justifyContent="space-between">
                                    <Box>
                                        <Typography variant="h6" fontWeight={700}>Passkeys</Typography>
                                        <Typography variant="body2" color="text.secondary">
                                            Register a passkey for passwordless or hardware-backed sign-ins.
                                        </Typography>
                                    </Box>
                                </Box>
                                {passkeyMessage ? (
                                    <Alert
                                        severity={passkeyMessage.type}
                                        onClose={() => setPasskeyMessage(null)}
                                    >
                                        {passkeyMessage.text}
                                    </Alert>
                                ) : null}
                                {!passkeySupported ? (
                                    <Alert severity="warning">
                                        Passkeys are not supported in this browser. Try updating or switching to a compatible
                                        browser.
                                    </Alert>
                                ) : (
                                    <Stack spacing={1.5}>
                                        <Typography variant="body2">
                                            Use your device or hardware security key to add another secure way to sign in.
                                        </Typography>
                                        <Button
                                            onClick={() => {
                                                void handleRegisterPasskey();
                                            }}
                                            variant="contained"
                                            disabled={passkeyBusy}
                                            startIcon={passkeyBusy
                                                ? <CircularProgress size={18} color="inherit"/>
                                                : <Key/>}
                                        >
                                            {passkeyBusy ? 'Waiting for confirmation…' : 'Register a passkey'}
                                        </Button>
                                    </Stack>
                                )}
                            </Stack>
                        </Stack>
                    </Stack>
                </DialogContent>
                <DialogActions sx={{px: 3, pb: 2}}>
                    <Button onClick={handleProfileDialogClose} disabled={avatarSaving}>Cancel</Button>
                    <Button
                        onClick={() => {
                            void handleAvatarSave();
                        }}
                        disabled={avatarSaving || !avatarChanged}
                        variant="contained"
                        disableElevation
                    >
                        {avatarSaving ? 'Saving…' : 'Save'}
                    </Button>
                </DialogActions>
            </Dialog>
            <Dialog
                open={openDialog}
                onClose={handleDialogClose}
                fullWidth
                maxWidth="sm"
                slotProps={{
                    backdrop: {sx: {backdropFilter: 'blur(8px)', backgroundColor: 'rgba(2,6,23,0.45)'}},
                    paper: {sx: {borderRadius: 4, backgroundImage: 'none'}},
                }}
            >
                <DialogTitle sx={{fontWeight: 800}}>
                    {dialogMode === 'edit' ? 'Edit item' : 'Add item'}
                </DialogTitle>
                <DialogContent>
                    <Stack spacing={1.5} marginTop={0.5}>
                        <TextField
                            label="Title"
                            value={title}
                            onChange={(e) => setTitle(e.target.value)}
                            placeholder="ex: Google"
                            fullWidth
                            size="small"
                        />
                        <TextField
                            label="Username / Email"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            placeholder="user@example.com"
                            fullWidth
                            size="small"
                        />
                        <Box>
                            <TextField
                                label="Password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="••••••••"
                                fullWidth
                                size="small"
                                error={passwordTooWeak}
                                type={showPwd ? 'text' : 'password'}
                                slotProps={{
                                    input: {
                                        endAdornment: (
                                            <InputAdornment position="end">
                                                <Tooltip title="Generate password">
                                                    <IconButton
                                                        onClick={handleGeneratorMenuOpen}
                                                        edge="end"
                                                        size="small"
                                                        aria-label="Generate password"
                                                    >
                                                        <AutoFixHigh fontSize="small"/>
                                                    </IconButton>
                                                </Tooltip>
                                                <Tooltip title={showPwd ? 'Hide password' : 'Show password'}>
                                                    <IconButton
                                                        onClick={() => setShowPwd((s) => !s)}
                                                        edge="end"
                                                        size="small"
                                                        aria-label={showPwd ? 'Hide password' : 'Show password'}
                                                    >
                                                        {showPwd ? <VisibilityOff fontSize="small"/> :
                                                            <Visibility fontSize="small"/>}
                                                    </IconButton>
                                                </Tooltip>
                                            </InputAdornment>
                                        ),
                                    },
                                }}
                            />
                            <LinearProgress
                                variant="determinate"
                                value={pwdProgress}
                                sx={{
                                    marginTop: 1,
                                    height: 6,
                                    borderRadius: 3,
                                    '& .MuiLinearProgress-bar': {
                                        background: strengthColor,
                                    },
                                }}
                            />
                            <Box sx={{mt: 0.5}}>
                                <Typography
                                    variant="caption"
                                    sx={{fontWeight: 600, display: 'block'}}
                                    color={pwdStrength.compromised ? 'error.main' : 'inherit'}
                                >
                                    {strengthLabel}
                                </Typography>
                                {password ? (
                                    <Typography
                                        variant="caption"
                                        color={pwdStrength.compromised ? 'error.main' : 'text.secondary'}
                                        sx={{display: 'block'}}
                                    >
                                        Estimated crack time: {pwdStrength.crackTime}
                                    </Typography>
                                ) : null}
                                <Stack
                                    component="ul"
                                    spacing={0.25}
                                    sx={{
                                        listStyleType: 'disc',
                                        pl: 2,
                                        mt: 0.5,
                                        mb: 0,
                                        color: pwdStrength.compromised ? 'error.main' : 'text.secondary',
                                    }}
                                >
                                    {strengthSuggestions.map((suggestion, index) => (
                                        <Typography key={`${suggestion}-${index}`} component="li" variant="caption">
                                            {suggestion}
                                        </Typography>
                                    ))}
                                </Stack>
                                {passwordWarning ? (
                                    <Typography
                                        variant="caption"
                                        color="error.main"
                                        sx={{display: 'block', fontWeight: 600, mt: 0.75}}
                                    >
                                        {passwordWarning}
                                    </Typography>
                                ) : null}
                            </Box>
                        </Box>
                        <TextField
                            label="Website (optional)"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            placeholder="https://example.com"
                            fullWidth
                            size="small"
                        />
                        <TextField
                            label="Tags (comma separated)"
                            value={tags}
                            onChange={(e) => setTags(e.target.value)}
                            placeholder="Social, Work, Finance"
                            fullWidth
                            size="small"
                        />
                        <TextField
                            label="Notes"
                            value={notes}
                            onChange={(e) => setNotes(e.target.value)}
                            placeholder="Secure notes..."
                            fullWidth
                            multiline
                            minRows={3}
                            size="small"
                        />
                        <TextField
                            label="TOTP Secret"
                            value={totpSecret}
                            onChange={(e) => setTotpSecret(e.target.value)}
                            placeholder="JBSWY3DPEHPK3PXP"
                            fullWidth
                            size="small"
                            type="password"
                        />
                    </Stack>
                </DialogContent>
                <Menu
                    anchorEl={generatorAnchorEl}
                    open={generatorMenuOpen}
                    onClose={handleGeneratorMenuClose}
                    anchorOrigin={{vertical: 'bottom', horizontal: 'right'}}
                    transformOrigin={{vertical: 'top', horizontal: 'right'}}
                >
                    {passwordTemplates.map((template) => (
                        <MenuItem key={template.id} onClick={() => handleSelectTemplate(template.id)}>
                            <ListItemText
                                primary={template.label}
                                secondary={template.description}
                                primaryTypographyProps={{fontWeight: 600}}
                                secondaryTypographyProps={{variant: 'caption', color: 'text.secondary'}}
                            />
                        </MenuItem>
                    ))}
                </Menu>
                <DialogActions sx={{px: 3, pb: 2}}>
                    <Button onClick={handleDialogClose} disabled={busy}>Cancel</Button>
                    <Button
                        onClick={() => {
                            void handleSave();
                        }}
                        disabled={saveDisabled}
                        variant="contained"
                        disableElevation
                    >
                        {busy ? 'Saving…' : dialogMode === 'edit' ? 'Save changes' : 'Save'}
                    </Button>
                </DialogActions>
            </Dialog>

            {/* Unlock Dialog (unchanged) */}
            <Dialog
                open={showUnlockDialog}
                onClose={() => closeUnlockDialog()}
                fullWidth
                maxWidth="xs"
                slotProps={{
                    backdrop: {sx: {backdropFilter: 'blur(8px)', backgroundColor: 'rgba(2,6,23,0.45)'}},
                    paper: {sx: {borderRadius: 4, backgroundImage: 'none'}},
                }}
            >
                <DialogTitle sx={{fontWeight: 800}}>{unlockDialogTitle}</DialogTitle>
                <DialogContent>
                    <Typography variant="body2" color="text.secondary" sx={{marginBottom: 2}}>
                        {unlockDialogDescription}
                    </Typography>
                    <TextField
                        fullWidth
                        autoFocus
                        label="Master password"
                        type={showUnlockPwd ? 'text' : 'password'}
                        value={unlockPassword}
                        onChange={(e) => setUnlockPassword(e.target.value)}
                        error={!!unlockError}
                        helperText={unlockError || ' '}
                        onKeyDown={(e) => {
                            if (e.key === 'Enter') handleUnlock();
                        }}
                        slotProps={{
                            input: {
                                endAdornment: (
                                    <InputAdornment position="end">
                                        <IconButton
                                            onClick={() => setShowUnlockPwd(!showUnlockPwd)}
                                            edge="end"
                                        >
                                            {showUnlockPwd ? <VisibilityOff/> : <Visibility/>}
                                        </IconButton>
                                    </InputAdornment>
                                ),
                            },
                        }}
                    />
                </DialogContent>
                <DialogActions sx={{px: 3, pb: 2}}>
                    <Button
                        onClick={() => closeUnlockDialog()}
                        disabled={unlockBusy}
                    >
                        Cancel
                    </Button>
                    <Button
                        onClick={() => {
                            void handleUnlock();
                        }}
                        disabled={!unlockPassword || unlockBusy}
                        variant="contained"
                        disableElevation
                    >
                        {unlockBusy ? 'Unlocking…' : 'Unlock'}
                    </Button>
                </DialogActions>
            </Dialog>

            {/* Delete confirmation */}
            <Dialog
                open={!!deleteTarget}
                onClose={handleDeleteDialogClose}
                fullWidth
                maxWidth="xs"
                slotProps={{
                    backdrop: {sx: {backdropFilter: 'blur(8px)', backgroundColor: 'rgba(2,6,23,0.45)'}},
                    paper: {sx: {borderRadius: 4, backgroundImage: 'none'}},
                }}
            >
                <DialogTitle sx={{fontWeight: 800}}>Delete item</DialogTitle>
                <DialogContent>
                    <DialogContentText>
                        Are you sure you want to delete "{deleteTarget?.name}"? This action cannot be undone.
                    </DialogContentText>
                </DialogContent>
                <DialogActions sx={{px: 3, pb: 2}}>
                    <Button onClick={handleDeleteDialogClose} disabled={deleteBusy}>Cancel</Button>
                    <Button
                        onClick={() => {
                            void handleDeleteConfirm();
                        }}
                        disabled={deleteBusy}
                        color="error"
                        variant="contained"
                        disableElevation
                    >
                        {deleteBusy ? 'Deleting…' : 'Delete'}
                    </Button>
                </DialogActions>
            </Dialog>

            <Snackbar
                open={!!toast}
                autoHideDuration={3500}
                anchorOrigin={{vertical: 'bottom', horizontal: 'center'}}
                onClose={() => setToast(null)}
            >
                {toast ? <Alert severity={toast.type}>{toast.msg}</Alert> : undefined}
            </Snackbar>
        </Box>
    );
}
