import {useMemo, useState, useEffect} from 'react';
import {useAuth} from '../auth/AuthContext';
import {useCrypto} from '../lib/crypto/CryptoContext';
import {api, type PublicCredential} from '../lib/api';
import Alert from '@mui/material/Alert';
import {deriveKEK} from '../lib/crypto/argon2';
import {unwrapDEK} from '../lib/crypto/unwrap';

import {
    Box, Drawer, List, ListItem, ListItemButton, ListItemIcon, ListItemText, Divider, Typography,
    Avatar, TextField, IconButton, Card, CardContent, Button, InputAdornment,
    Dialog, DialogTitle, DialogContent, DialogActions, Snackbar, Stack, LinearProgress,
} from '@mui/material';

import {
    Search, AccountBox, CreditCard, Note, Wifi, Key, Assignment, Star, Edit,
    Add as AddIcon, Visibility, VisibilityOff, Link as LinkIcon,
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

const categories = [
    {text: 'Logins', icon: <Key/>},
    {text: 'Secure Notes', icon: <Note/>},
    {text: 'Credit Cards', icon: <CreditCard/>},
    {text: 'Identities', icon: <AccountBox/>},
    {text: 'Software Licenses', icon: <Assignment/>},
    {text: 'Wireless Routers', icon: <Wifi/>},
];

const te = new TextEncoder();
const toB64 = (buf: ArrayBuffer | Uint8Array) =>
    btoa(String.fromCharCode(...new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer)));
const randIv = (len = 12) => crypto.getRandomValues(new Uint8Array(len));

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
    const {user, logout} = useAuth();
    const {dek, locked, setDEK} = useCrypto();

    const [credentials, setCredentials] = useState<Credential[]>([]);
    const [selected, setSelected] = useState<Credential | null>(null);

    const [openAdd, setOpenAdd] = useState(false);
    const [showUnlockForAdd, setShowUnlockForAdd] = useState(false);
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
    const [toast, setToast] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);

    const pwdScore = useMemo(() => scorePassword(password), [password]);
    const saveDisabled = busy || !title.trim() || !username.trim() || !password;

    // Reset UI when vault is locked or DEK changes to a locked state
    useEffect(() => {
        if (!locked && dek) return;

        setCredentials([]);
        setSelected(null);
        setOpenAdd(false);
        setShowUnlockForAdd(false);
        setTitle('');
        setUsername('');
        setPassword('');
        setUrl('');
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
                const {credentials: encCreds}: {credentials: PublicCredential[]} =
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
            setUnlockPassword('');
            setShowUnlockForAdd(false);
            setOpenAdd(true);
        } catch {
            setUnlockError('Master password invalid');
        } finally {
            setUnlockBusy(false);
        }
    };

    async function handleAddSave() {
        try {
            if (!dek) throw new Error('Session not ready. Unlock vault and try again.');
            setBusy(true);

            const {cipher: usernameCipher, nonce: usernameNonce} = await encryptField(dek, username);
            const {cipher: passwordCipher, nonce: passwordNonce} = await encryptField(dek, password);

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
                name: title.trim(),
                url: url.trim() || undefined,
                username: username.trim(),
                password: password,
            };

            setCredentials((prev) => [newCredential, ...prev]);
            setSelected(newCredential);

            setTitle('');
            setUsername('');
            setPassword('');
            setUrl('');
            setOpenAdd(false);
            setToast({type: 'success', msg: 'Saved to /api/credentials (encrypted).'});
        } catch (e: unknown) {
            const message = e instanceof Error ? e.message : 'Failed to save';
            setToast({type: 'error', msg: message || 'Failed to save'});
        } finally {
            setBusy(false);
        }
    }

    return (
        <Box display="flex" minHeight="100vh" sx={{bgcolor: 'background.default'}}>
            <Drawer
                variant="permanent"
                anchor="left"
                PaperProps={{
                    sx: {
                        width: 260,
                        borderRight: '1px solid',
                        borderColor: 'divider',
                        bgcolor: 'background.paper',
                    },
                }}
            >
                <Box p={2}>
                    <Typography variant="h6" fontWeight={700} gutterBottom>
                        All Credentials ({credentials.length})
                    </Typography>
                </Box>
                <Divider/>
                <List dense>
                    {categories.map((cat) => (
                        <ListItemButton key={cat.text}>
                            <ListItemIcon sx={{minWidth: 36}}>{cat.icon}</ListItemIcon>
                            <ListItemText primary={cat.text}/>
                        </ListItemButton>
                    ))}
                </List>
            </Drawer>

            <Box flex={1} p={3} ml={{xs: 0, md: '260px'}}>
                <Box display="flex" alignItems="center" justifyContent="space-between" mb={2} gap={2}>
                    <TextField
                        placeholder="Search"
                        size="small"
                        sx={{maxWidth: 420}}
                        InputProps={{
                            startAdornment: (
                                <InputAdornment position="start">
                                    <Search fontSize="small"/>
                                </InputAdornment>
                            ),
                        }}
                    />
                    <Box display="flex" alignItems="center" gap={2}>
                        <Button onClick={() => { void logout(); }} variant="outlined" size="small">
                            Log out
                        </Button>
                        <Avatar alt={user?.email ?? 'User'} src="/avatar.png"/>
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
                            ) : (
                                credentials.map((credential) => {
                                    const active = selected?.id === credential.id;
                                    return (
                                        <ListItemButton
                                            key={credential.id}
                                            selected={!!active}
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
                                <Box display="flex" flexDirection="column" alignItems="center" justifyContent="center" minHeight={360} textAlign="center" gap={1}>
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
                                                onClick={() => {
                                                    if (!dek || locked) {
                                                        setShowUnlockForAdd(true);
                                                        return;
                                                    }
                                                    setOpenAdd(true);
                                                }}
                                                title="Add credential"
                                            >
                                                <AddIcon/>
                                            </IconButton>
                                            <IconButton size="small">
                                                <Star color="warning"/>
                                            </IconButton>
                                            <IconButton size="small">
                                                <Edit/>
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

            {/* Add Credential Dialog */}
            <Dialog
                open={openAdd}
                onClose={() => (!busy ? setOpenAdd(false) : undefined)}
                fullWidth
                maxWidth="sm"
                slotProps={{backdrop: {sx: {backdropFilter: 'blur(8px)', backgroundColor: 'rgba(2,6,23,0.45)'}}}}
                PaperProps={{sx: {borderRadius: 4, backgroundImage: 'none'}}}
            >
                <DialogTitle sx={{fontWeight: 800}}>Add credential</DialogTitle>
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
                                InputProps={{
                                    endAdornment: (
                                        <InputAdornment position="end">
                                            <IconButton onClick={() => setShowPwd((s) => !s)} edge="end">
                                                {showPwd ? <VisibilityOff/> : <Visibility/>}
                                            </IconButton>
                                        </InputAdornment>
                                    ),
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
                    <Button onClick={() => setOpenAdd(false)} disabled={busy}>Cancel</Button>
                    <Button
                        onClick={handleAddSave}
                        disabled={saveDisabled}
                        variant="contained"
                        sx={{fontWeight: 800, background: 'linear-gradient(90deg,#2563eb,#6366f1 50%,#7c3aed)'}}
                    >
                        {busy ? 'Saving…' : 'Save'}
                    </Button>
                </DialogActions>
            </Dialog>

            {/* Unlock Dialog */}
            <Dialog
                open={showUnlockForAdd}
                onClose={() => setShowUnlockForAdd(false)}
                fullWidth
                maxWidth="xs"
                slotProps={{backdrop: {sx: {backdropFilter: 'blur(8px)', backgroundColor: 'rgba(2,6,23,0.45)'}}}}
                PaperProps={{sx: {borderRadius: 4, backgroundImage: 'none'}}}
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
                        InputProps={{
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
                        }}
                    />
                </DialogContent>
                <DialogActions sx={{px: 3, pb: 2}}>
                    <Button
                        onClick={() => {
                            setShowUnlockForAdd(false);
                            setUnlockPassword('');
                            setUnlockError(null);
                        }}
                        disabled={unlockBusy}
                    >
                        Cancel
                    </Button>
                    <Button
                        onClick={handleUnlock}
                        disabled={!unlockPassword || unlockBusy}
                        variant="contained"
                        sx={{fontWeight: 800, background: 'linear-gradient(90deg,#2563eb,#6366f1 50%,#7c3aed)'}}
                    >
                        {unlockBusy ? 'Unlocking…' : 'Unlock'}
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
