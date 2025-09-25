import {useMemo, useState, useEffect} from 'react';
import {useNavigate} from 'react-router-dom';
import type {ChangeEvent} from 'react';
import {useAuth} from '../auth/auth-context';
import {useCrypto} from '../lib/crypto/crypto-context';
import {api, type PublicCredential} from '../lib/api';
import {isAuditAdminEmail} from '../lib/accessControl';
import Alert from '@mui/material/Alert';
import {deriveKEK} from '../lib/crypto/argon2';
import {unwrapDEK} from '../lib/crypto/unwrap';

import {
    Box, Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Divider, Typography,
    Avatar, TextField, IconButton, Card, CardContent, Button, InputAdornment,
    Dialog, DialogTitle, DialogContent, DialogActions, DialogContentText, Snackbar, Stack, LinearProgress,
} from '@mui/material';

import {
    Search, Note, Key, Star, Edit, Delete,
    Add as AddIcon, Visibility, VisibilityOff, Link as LinkIcon, Settings, Upload, DeleteOutline, ListAlt,
} from '@mui/icons-material';

const td = new TextDecoder();

async function decryptField(dek: CryptoKey, cipher: string, nonce: string) {
    const ct = Uint8Array.from(atob(cipher), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(nonce), c => c.charCodeAt(0));
    const pt = await crypto.subtle.decrypt({name: 'AES-GCM', iv}, dek, ct);
    return td.decode(pt);
}

export type Credential = {
    id: string;
    name: string;
    url?: string;
    username: string;
    password: string;
}

const ALL_CATEGORY_ID = '__all__';
const UNCATEGORIZED_LABEL = 'Uncategorized';

type CategoryItem = {
    id: string;
    label: string;
    count: number;
};

function inferCategory(credential: Credential): string {
    const url = credential.url?.trim();
    if (url) {
        try {
            const normalized = url.includes('://') ? url : `https://${url}`;
            const parsed = new URL(normalized);
            const hostname = parsed.hostname.replace(/^www\./i, '').trim();
            if (hostname) {
                return hostname;
            }
        } catch {
            // ignore parsing errors and fall back to other strategies
        }
    }

    const name = credential.name.trim();
    if (name) {
        return name;
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

function scorePassword(p: string) {
    let s = 0;
    if (p.length >= 8) s++;
    if (/[A-Z]/.test(p)) s++;
    if (/[a-z]/.test(p)) s++;
    if (/\d/.test(p)) s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;
    return Math.min(s, 5);
}

export default function Dashboard() {
    const {user, logout, login} = useAuth();
    const {dek, locked, setDEK} = useCrypto();
    const navigate = useNavigate();

    const [credentials, setCredentials] = useState<Credential[]>([]);
    const [selected, setSelected] = useState<Credential | null>(null);

    const [dialogMode, setDialogMode] = useState<'add' | 'edit' | null>(null);
    const [editingTarget, setEditingTarget] = useState<Credential | null>(null);
    const [pendingDialogMode, setPendingDialogMode] = useState<'add' | 'edit' | null>(null);
    const [pendingEditTarget, setPendingEditTarget] = useState<Credential | null>(null);
    const openDialog = dialogMode !== null;

    const [showUnlockDialog, setShowUnlockDialog] = useState(false);
    const [unlockPassword, setUnlockPassword] = useState('');
    const [showUnlockPwd, setShowUnlockPwd] = useState(false);
    const [unlockBusy, setUnlockBusy] = useState(false);
    const [unlockError, setUnlockError] = useState<string | null>(null);

    const [title, setTitle] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [url, setUrl] = useState('');
    const [showPwd, setShowPwd] = useState(false);
    const [busy, setBusy] = useState(false);
    const [deleteBusy, setDeleteBusy] = useState(false);
    const [deleteTarget, setDeleteTarget] = useState<Credential | null>(null);
    const [toast, setToast] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);
    const [avatarLoadError, setAvatarLoadError] = useState(false);
    const [profileDialogOpen, setProfileDialogOpen] = useState(false);
    const [avatarPreview, setAvatarPreview] = useState<string | null>(null);
    const [avatarDialogError, setAvatarDialogError] = useState<string | null>(null);
    const [avatarSaving, setAvatarSaving] = useState(false);
    const [searchQuery, setSearchQuery] = useState('');
    const [selectedCategory, setSelectedCategory] = useState<string>(ALL_CATEGORY_ID);

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

    const pwdScore = useMemo(() => scorePassword(password), [password]);
    const saveDisabled = busy || !title.trim() || !username.trim() || !password;

    useEffect(() => {
        if (!locked && dek) return;

        setCredentials([]);
        setSelected(null);
        setDialogMode(null);
        setEditingTarget(null);
        setPendingDialogMode(null);
        setPendingEditTarget(null);
        setShowUnlockDialog(false);
        setUnlockPassword('');
        setUnlockError(null);
        setShowUnlockPwd(false);
        setTitle('');
        setUsername('');
        setPassword('');
        setUrl('');
        setShowPwd(false);
        setBusy(false);
        setDeleteBusy(false);
        setDeleteTarget(null);
        setSearchQuery('');
        setSelectedCategory(ALL_CATEGORY_ID);
    }, [dek, locked]);

    useEffect(() => {
        console.log("useEffect triggered", {dek, user});

        if (!dek) {
            console.log("No DEK yet → vault still locked");
            return;
        }
        if (!user) {
            console.log("No authenticated user → not logged in");
            return;
        }

        (async () => {
            console.log("Calling /api/credentials");
            try {
                console.log("trying to fetch credentials");
                const {credentials: encCreds}: { credentials: PublicCredential[] } =
                    await api.fetchCredentials();

                const decrypted: Credential[] = [];
                for (const enc of encCreds) {
                    const {
                        credentialId,
                        service,
                        websiteLink,
                        usernameEncrypted,
                        usernameNonce,
                        passwordEncrypted,
                        passwordNonce,
                    } = enc;
                    const username = await decryptField(dek, usernameEncrypted, usernameNonce);
                    const password = await decryptField(dek, passwordEncrypted, passwordNonce);
                    decrypted.push({
                        id: credentialId,
                        name: service,
                        url: websiteLink || undefined,
                        username,
                        password,
                    });
                }

                setCredentials(decrypted);
                setSelected(decrypted[0] ?? null);
            } catch (err: unknown) {
                const message = err instanceof Error ? err.message : 'Failed to load credentials';
                setToast({type: 'error', msg: message || 'Failed to load credentials'});
            }
        })();
    }, [dek, user]);

    useEffect(() => {
        setAvatarLoadError(false);
    }, [user?.avatarData, user?.email]);

    const categoryItems = useMemo<CategoryItem[]>(() => {
        const counts = new Map<string, number>();
        for (const credential of credentials) {
            const category = inferCategory(credential);
            counts.set(category, (counts.get(category) ?? 0) + 1);
        }

        const dynamic = Array.from(counts.entries())
            .sort((a, b) => a[0].localeCompare(b[0], undefined, {sensitivity: 'base'}))
            .map<CategoryItem>(([label, count]) => ({
                id: label,
                label,
                count,
            }));

        return [
            {id: ALL_CATEGORY_ID, label: 'All credentials', count: credentials.length},
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
                const category = inferCategory(credential);
                if (category !== selectedCategory) {
                    return false;
                }
            }

            if (!normalizedQuery) {
                return true;
            }

            const haystack = [credential.name, credential.username, credential.url ?? ''];
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
            setPendingDialogMode('add');
            setPendingEditTarget(null);
            setShowUnlockDialog(true);
            return;
        }
        openAddDialog();
    };

    const handleEditClick = () => {
        if (!selected) return;
        if (!dek || locked) {
            setPendingDialogMode('edit');
            setPendingEditTarget(selected);
            setShowUnlockDialog(true);
            return;
        }
        openEditDialog(selected);
    };

    const handleDeleteClick = () => {
        if (!selected) return;
        setDeleteTarget(selected);
    };

    const closeUnlockDialog = () => {
        if (unlockBusy) return;
        setShowUnlockDialog(false);
        setUnlockPassword('');
        setUnlockError(null);
        setShowUnlockPwd(false);
        setPendingDialogMode(null);
        setPendingEditTarget(null);
    };

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
            setDEK(dekKey);
            const nextMode = pendingDialogMode;
            const nextEditTarget = pendingEditTarget;
            setPendingDialogMode(null);
            setPendingEditTarget(null);
            setUnlockPassword('');
            setShowUnlockDialog(false);
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

            const trimmedTitle = title.trim();
            const trimmedUrl = url.trim();
            const trimmedUsername = username.trim();

            if (dialogMode === 'add') {
                const created = await api.createCredential({
                    title,
                    url,
                    usernameCipher,
                    usernameNonce,
                    passwordCipher,
                    passwordNonce,
                });

                const newCredential: Credential = {
                    id: created.credentialId,
                    name: trimmedTitle,
                    url: trimmedUrl || undefined,
                    username: trimmedUsername,
                    password: password,
                };

                setCredentials((prev) => [newCredential, ...prev]);
                setSelected(newCredential);
                setToast({type: 'success', msg: 'Saved to /api/credentials (encrypted).'});
            } else if (dialogMode === 'edit' && editingTarget) {
                await api.updateCredential(editingTarget.id, {
                    service: title,
                    websiteLink: trimmedUrl || undefined,
                    usernameEncrypted: usernameCipher,
                    usernameNonce,
                    passwordEncrypted: passwordCipher,
                    passwordNonce,
                });

                const updatedCredential: Credential = {
                    id: editingTarget.id,
                    name: trimmedTitle,
                    url: trimmedUrl || undefined,
                    username: trimmedUsername,
                    password: password,
                };

                setCredentials((prev) =>
                    prev.map((cred) => (cred.id === editingTarget.id ? updatedCredential : cred)),
                );
                setSelected((prevSelected) =>
                    prevSelected && prevSelected.id === editingTarget.id ? updatedCredential : prevSelected,
                );
                setToast({type: 'success', msg: 'Credential updated.'});
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
            await api.deleteCredential(deleteTarget.id);
            setCredentials((prev) => {
                const next = prev.filter((cred) => cred.id !== deleteTarget.id);
                if (selected?.id === deleteTarget.id) {
                    setSelected(next[0] ?? null);
                }
                return next;
            });
            setToast({type: 'success', msg: 'Credential deleted.'});
            setDeleteTarget(null);
        } catch (e: unknown) {
            const message = e instanceof Error ? e.message : 'Failed to delete credential';
            setToast({type: 'error', msg: message || 'Failed to delete credential'});
        } finally {
            setDeleteBusy(false);
        }
    };

    const handleDeleteDialogClose = () => {
        if (deleteBusy) return;
        setDeleteTarget(null);
    };

    return (
        <Box display="flex" minHeight="100vh" sx={{bgcolor: 'background.default'}}>
            <Drawer
                variant="permanent"
                anchor="left"
                slotProps={{
                    paper: {
                        sx: {
                            width: 260,
                            borderRight: '1px solid',
                            borderColor: 'divider',
                            bgcolor: 'background.paper',
                        },
                    },
                }}
            >
                <Box p={2}>
                    <Typography variant="h6" fontWeight={700} gutterBottom>
                        {activeCategory
                            ? `${activeCategory.label} (${activeCategory.count})`
                            : `All Credentials (${credentials.length})`}
                    </Typography>
                </Box>
                <Divider/>
                <List dense>
                    {categoryItems.map((category) => (
                        <ListItemButton
                            key={category.id}
                            selected={selectedCategory === category.id}
                            onClick={() => setSelectedCategory(category.id)}
                        >
                            <ListItemIcon sx={{minWidth: 36}}>{renderCategoryIcon(category.id)}</ListItemIcon>
                            <ListItemText primary={`${category.label} (${category.count})`}/>
                        </ListItemButton>
                    ))}
                </List>
            </Drawer>

            <Box flex={1} p={3} ml={{xs: 0, md: '260px'}}>
                <Box display="flex" alignItems="center" justifyContent="space-between" mb={2} gap={2}>
                    <TextField
                        placeholder="Search"
                        value={searchQuery}
                        onChange={(event) => setSearchQuery(event.target.value)}
                        size="small"
                        sx={{maxWidth: 420}}
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
                    <Box display="flex" alignItems="center" gap={2}>
                        {isAuditAdmin && (
                            <Button
                                onClick={() => navigate('/audit-log')}
                                variant="contained"
                                size="small"
                                startIcon={<ListAlt fontSize="small"/>}
                                color="secondary"
                            >
                                Audit log
                            </Button>
                        )}
                        <Button
                            onClick={handleProfileDialogOpen}
                            variant="outlined"
                            size="small"
                            startIcon={<Settings fontSize="small"/>}
                        >
                            Settings
                        </Button>
                        <Button onClick={() => {
                            void logout();
                        }} variant="outlined" size="small">
                            Log out
                        </Button>
                        <Avatar
                            alt={user?.email ?? 'User'}
                            src={avatarLoadError ? undefined : avatarSrc ?? undefined}
                            slotProps={{ img: { onError: () => setAvatarLoadError(true) } }}
                        >
                            {avatarInitials}
                        </Avatar>
                        <Typography variant="body2">{user?.email ?? 'No user email found'}</Typography>
                    </Box>
                </Box>

                <Box display="grid" gridTemplateColumns={{xs: '1fr', md: '280px 1fr'}} gap={2}>
                    <Card variant="outlined" sx={{overflow: 'hidden'}}>
                        <List dense disablePadding>
                            {locked ? (
                                <ListItem>
                                    <ListItemText primary="Vault locked" secondary="Unlock to view credentials."/>
                                </ListItem>
                            ) : filteredCredentials.length === 0 ? (
                                <ListItem>
                                    <ListItemText
                                        primary={
                                            searchQuery
                                                ? 'No credentials match your search.'
                                                : 'No credentials in this category yet.'
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
                                                    bgcolor: (t) =>
                                                        t.palette.mode === 'dark'
                                                            ? 'rgba(99,102,241,.12)'
                                                            : 'rgba(99,102,241,.08)',
                                                },
                                            }}
                                        >
                                            <ListItemText primary={credential.name}
                                                          secondary={credential.username || '—'}/>
                                        </ListItemButton>
                                    );
                                })
                            )}
                        </List>
                    </Card>

                    <Card sx={{minHeight: 420}}>
                        <CardContent>
                            {locked ? (
                                <Box display="flex" flexDirection="column" alignItems="center" justifyContent="center"
                                     minHeight={360} textAlign="center" gap={1}>
                                    <Typography variant="h6" fontWeight={700}>Vault locked</Typography>
                                    <Typography variant="body2" color="text.secondary">
                                        Unlock your vault to view credential details.
                                    </Typography>
                                </Box>
                            ) : (
                                <>
                                    <Box display="flex" justifyContent="space-between" alignItems="center" mb={1.5}>
                                        <Typography variant="h6" fontWeight={700}>
                                            {selected?.name || 'Select a credential'}
                                        </Typography>
                                        <Box>
                                            <IconButton
                                                size="small"
                                                onClick={handleAddClick}
                                                title="Add credential"
                                            >
                                                <AddIcon/>
                                            </IconButton>
                                            <IconButton size="small">
                                                <Star color="warning"/>
                                            </IconButton>
                                            <IconButton
                                                size="small"
                                                onClick={handleEditClick}
                                                disabled={!selected}
                                                title="Edit credential"
                                            >
                                                <Edit/>
                                            </IconButton>
                                            <IconButton
                                                size="small"
                                                onClick={handleDeleteClick}
                                                disabled={!selected}
                                                title="Delete credential"
                                                color="error"
                                            >
                                                <Delete/>
                                            </IconButton>
                                        </Box>
                                    </Box>

                                    <Typography variant="caption" color="text.secondary">username</Typography>
                                    <Typography sx={{mb: 1}}>{selected?.username || '—'}</Typography>

                                    <Typography variant="caption" color="text.secondary">password</Typography>
                                    <Typography sx={{mb: 1}}>••••••••</Typography>

                                    <Typography variant="caption" color="text.secondary">strength</Typography>
                                    <Box sx={{
                                        height: 8,
                                        width: 140,
                                        backgroundColor: 'action.hover',
                                        borderRadius: 4,
                                        mt: 0.5,
                                        mb: 2
                                    }}>
                                        <Box sx={{
                                            height: '100%',
                                            width: '40%',
                                            backgroundColor: 'success.main',
                                            borderRadius: 4
                                        }}/>
                                    </Box>

                                    <Typography variant="caption" color="text.secondary">website</Typography>
                                    <Box>
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
                                </>
                            )}
                        </CardContent>
                    </Card>
                </Box>
            </Box>


            {/* Profile settings dialog */}
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
                        sx={{fontWeight: 800, background: 'linear-gradient(90deg,#2563eb,#6366f1 50%,#7c3aed)'}}
                    >
                        {avatarSaving ? 'Saving…' : 'Save'}
                    </Button>
                </DialogActions>
            </Dialog>

            {/* Add Credential Dialog */}
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
                    {dialogMode === 'edit' ? 'Edit credential' : 'Add credential'}
                </DialogTitle>
                <DialogContent>
                    <Stack spacing={1.5} mt={0.5}>
                        <TextField
                            label="Title (service)"
                            value={title}
                            onChange={(e) => setTitle(e.target.value)}
                            placeholder="ex: Evernote"
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
                                type={showPwd ? 'text' : 'password'}
                                slotProps={{
                                    input: {
                                        endAdornment: (
                                            <InputAdornment position="end">
                                                <IconButton onClick={() => setShowPwd((s) => !s)} edge="end">
                                                    {showPwd ? <VisibilityOff/> : <Visibility/>}
                                                </IconButton>
                                            </InputAdornment>
                                        ),
                                    },
                                }}
                            />
                            <LinearProgress
                                variant="determinate"
                                value={(pwdScore / 5) * 100}
                                sx={{
                                    mt: 1,
                                    height: 6,
                                    borderRadius: 3,
                                    '& .MuiLinearProgress-bar': {
                                        background: ['#ef4444', '#f59e0b', '#10b981', '#22c55e', '#16a34a'][Math.max(0, pwdScore - 1)],
                                    },
                                }}
                            />
                        </Box>
                        <TextField
                            label="Website (optional)"
                            value={url}
                            onChange={(e) => setUrl(e.target.value)}
                            placeholder="https://example.com"
                            fullWidth
                            size="small"
                        />
                    </Stack>
                </DialogContent>
                <DialogActions sx={{px: 3, pb: 2}}>
                    <Button onClick={handleDialogClose} disabled={busy}>Cancel</Button>
                    <Button
                        onClick={() => {
                            void handleSave();
                        }}
                        disabled={saveDisabled}
                        variant="contained"
                        sx={{fontWeight: 800, background: 'linear-gradient(90deg,#2563eb,#6366f1 50%,#7c3aed)'}}
                    >
                        {busy ? 'Saving…' : dialogMode === 'edit' ? 'Save changes' : 'Save'}
                    </Button>
                </DialogActions>
            </Dialog>

            {/* Unlock Dialog */}
            <Dialog
                open={showUnlockDialog}
                onClose={closeUnlockDialog}
                fullWidth
                maxWidth="xs"
                slotProps={{
                    backdrop: {sx: {backdropFilter: 'blur(8px)', backgroundColor: 'rgba(2,6,23,0.45)'}},
                    paper: {sx: {borderRadius: 4, backgroundImage: 'none'}},
                }}
            >
                <DialogTitle sx={{fontWeight: 800}}>Unlock Vault to Add Credential</DialogTitle>
                <DialogContent>
                    <Typography variant="body2" color="text.secondary" sx={{mb: 2}}>
                        Your vault is currently locked. Please enter your master password to unlock it and add new
                        credentials.
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
                        onClick={closeUnlockDialog}
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
                        sx={{fontWeight: 800, background: 'linear-gradient(90deg,#2563eb,#6366f1 50%,#7c3aed)'}}
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
                <DialogTitle sx={{fontWeight: 800}}>Delete credential</DialogTitle>
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
                        sx={{fontWeight: 800}}
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
