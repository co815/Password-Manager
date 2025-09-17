import { useMemo, useState } from 'react';
import { useAuth } from '../auth/AuthContext';
import { useCrypto } from '../lib/crypto/CryptoContext';
import { api } from '../lib/api';
import Alert from '@mui/material/Alert';

import {
    Box, Drawer, List, ListItemButton, ListItemIcon, ListItemText, Divider, Typography,
    Avatar, TextField, IconButton, Card, CardContent, Button, InputAdornment,
    Dialog, DialogTitle, DialogContent, DialogActions, Snackbar, Stack, LinearProgress,
} from '@mui/material';

import {
    Search, AccountBox, CreditCard, Note, Wifi, Key, Assignment, Star, Edit,
    Add as AddIcon, Visibility, VisibilityOff, Link as LinkIcon,
} from '@mui/icons-material';

type Item = { name: string; username: string; url?: string };

const categories = [
    { text: 'Logins', icon: <Key /> },
    { text: 'Secure Notes', icon: <Note /> },
    { text: 'Credit Cards', icon: <CreditCard /> },
    { text: 'Identities', icon: <AccountBox /> },
    { text: 'Software Licenses', icon: <Assignment /> },
    { text: 'Wireless Routers', icon: <Wifi /> },
];

const te = new TextEncoder();
const toB64 = (buf: ArrayBuffer | Uint8Array) =>
    btoa(String.fromCharCode(...new Uint8Array(buf instanceof ArrayBuffer ? buf : buf.buffer)));
const randIv = (len = 12) => crypto.getRandomValues(new Uint8Array(len));
async function encryptField(dek: CryptoKey, text: string) {
    const iv = randIv();
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dek, te.encode(text ?? ''));
    return { cipher: toB64(ct), nonce: toB64(iv) } as { cipher: string; nonce: string };
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
    const { user, logout } = useAuth();
    const { dek } = useCrypto();

    const [items, setItems] = useState<Item[]>([
        { name: "Driver's License", username: 'D6101-40706-60905' },
        { name: 'Dropbox', username: 'wendy.c.appleseed@gmail.com', url: 'https://dropbox.com' },
        { name: 'E*TRADE', username: 'wendy.c.appleseed@gmail.com', url: 'https://us.etrade.com' },
        { name: 'Evernote', username: 'wendy_appleseed@agilebits.com', url: 'https://evernote.com' },
        { name: 'Facebook', username: 'wendy.c.appleseed@gmail.com', url: 'https://facebook.com' },
        { name: 'Fantastical', username: '2' },
        { name: 'Gift Shopping List', username: '' },
        { name: 'Google', username: 'wendy.c.appleseed@gmail.com', url: 'https://google.com' },
    ]);
    const [selected, setSelected] = useState<Item>(items[3]);

    const [openAdd, setOpenAdd] = useState(false);
    const [title, setTitle] = useState('');
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [url, setUrl] = useState('');
    const [showPwd, setShowPwd] = useState(false);
    const [busy, setBusy] = useState(false);
    const [toast, setToast] = useState<{ type: 'success' | 'error'; msg: string } | null>(null);

    const pwdScore = useMemo(() => scorePassword(password), [password]);
    const saveDisabled = busy || !title.trim() || !username.trim() || !password;

    async function handleAddSave() {
        try {
            if (!dek) throw new Error('Session not ready. Unlock vault and try again.');
            setBusy(true);

            const { cipher: usernameCipher, nonce: usernameNonce } = await encryptField(dek, username);
            const { cipher: passwordCipher, nonce: passwordNonce } = await encryptField(dek, password);

            await api.createCredential({
                title,
                url,
                usernameCipher,
                usernameNonce,
                passwordCipher,
                passwordNonce,
            });

            const newItem: Item = { name: title.trim(), username: username.trim(), url: url.trim() || undefined };
            setItems((prev) => [newItem, ...prev]);
            setSelected(newItem);

            setTitle(''); setUsername(''); setPassword(''); setUrl('');
            setOpenAdd(false);
            setToast({ type: 'success', msg: 'Saved to /api/credentials (encrypted).' });
        } catch (e: any) {
            setToast({ type: 'error', msg: e?.message || 'Failed to save' });
        } finally {
            setBusy(false);
        }
    }

    return (
        <Box display="flex" minHeight="100vh" sx={{ bgcolor: 'background.default' }}>
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
                        All Items ({items.length})
                    </Typography>
                </Box>
                <Divider />
                <List dense>
                    {categories.map((cat) => (
                        <ListItemButton key={cat.text}>
                            <ListItemIcon sx={{ minWidth: 36 }}>{cat.icon}</ListItemIcon>
                            <ListItemText primary={cat.text} />
                        </ListItemButton>
                    ))}
                </List>
            </Drawer>

            <Box flex={1} p={3} ml={{ xs: 0, md: '260px' }}>
                <Box display="flex" alignItems="center" justifyContent="space-between" mb={2} gap={2}>
                    <TextField
                        placeholder="Search"
                        size="small"
                        sx={{ maxWidth: 420 }}
                        InputProps={{
                            startAdornment: (
                                <InputAdornment position="start">
                                    <Search fontSize="small" />
                                </InputAdornment>
                            ),
                        }}
                    />
                    <Box display="flex" alignItems="center" gap={2}>
                        <Button onClick={logout} variant="outlined" size="small">
                            Log out
                        </Button>
                        <Avatar alt={user?.email ?? 'User'} src="/avatar.png" />
                        <Typography variant="body2">{user?.email ?? 'No user email found'}</Typography>
                    </Box>
                </Box>

                <Box display="grid" gridTemplateColumns={{ xs: '1fr', md: '280px 1fr' }} gap={2}>
                    <Card variant="outlined" sx={{ overflow: 'hidden' }}>
                        <List dense disablePadding>
                            {items.map((item) => {
                                const active = selected?.name === item.name && selected?.username === item.username;
                                return (
                                    <ListItemButton
                                        key={`${item.name}-${item.username}`}
                                        selected={!!active}
                                        onClick={() => setSelected(item)}
                                        sx={{
                                            '&.Mui-selected': {
                                                bgcolor: (t) =>
                                                    t.palette.mode === 'dark' ? 'rgba(99,102,241,.12)' : 'rgba(99,102,241,.08)',
                                            },
                                        }}
                                    >
                                        <ListItemText primary={item.name} secondary={item.username || '—'} />
                                    </ListItemButton>
                                );
                            })}
                        </List>
                    </Card>

                    <Card sx={{ minHeight: 420 }}>
                        <CardContent>
                            <Box display="flex" justifyContent="space-between" alignItems="center" mb={1.5}>
                                <Typography variant="h6" fontWeight={700}>
                                    {selected?.name}
                                </Typography>
                                <Box>
                                    <IconButton size="small" onClick={() => setOpenAdd(true)} title="Add credential">
                                        <AddIcon />
                                    </IconButton>
                                    <IconButton size="small">
                                        <Star color="warning" />
                                    </IconButton>
                                    <IconButton size="small">
                                        <Edit />
                                    </IconButton>
                                </Box>
                            </Box>

                            <Typography variant="caption" color="text.secondary">username</Typography>
                            <Typography sx={{ mb: 1 }}>{selected?.username || '—'}</Typography>

                            <Typography variant="caption" color="text.secondary">password</Typography>
                            <Typography sx={{ mb: 1 }}>••••••••</Typography>

                            <Typography variant="caption" color="text.secondary">strength</Typography>
                            <Box sx={{ height: 8, width: 140, backgroundColor: 'action.hover', borderRadius: 4, mt: 0.5, mb: 2 }}>
                                <Box sx={{ height: '100%', width: '40%', backgroundColor: 'success.main', borderRadius: 4 }} />
                            </Box>

                            <Typography variant="caption" color="text.secondary">website</Typography>
                            <Box>
                                {selected?.url ? (
                                    <Button
                                        href={selected.url}
                                        target="_blank"
                                        rel="noreferrer"
                                        size="small"
                                        startIcon={<LinkIcon />}
                                    >
                                        {(() => { try { return new URL(selected.url!).hostname; } catch { return selected.url; } })()}
                                    </Button>
                                ) : (
                                    <Typography variant="body2" color="text.secondary">—</Typography>
                                )}
                            </Box>
                        </CardContent>
                    </Card>
                </Box>
            </Box>

            <Dialog
                open={openAdd}
                onClose={() => (!busy ? setOpenAdd(false) : undefined)}
                fullWidth
                maxWidth="sm"
                slotProps={{ backdrop: { sx: { backdropFilter: 'blur(8px)', backgroundColor: 'rgba(2,6,23,0.45)' } } }}
                PaperProps={{ sx: { borderRadius: 4, backgroundImage: 'none' } }}
            >
                <DialogTitle sx={{ fontWeight: 800 }}>Add credential</DialogTitle>
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
                                                {showPwd ? <VisibilityOff /> : <Visibility />}
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
                <DialogActions sx={{ px: 3, pb: 2 }}>
                    <Button onClick={() => setOpenAdd(false)} disabled={busy}>Cancel</Button>
                    <Button
                        onClick={handleAddSave}
                        disabled={saveDisabled}
                        variant="contained"
                        sx={{ fontWeight: 800, background: 'linear-gradient(90deg,#2563eb,#6366f1 50%,#7c3aed)' }}
                    >
                        {busy ? 'Saving…' : 'Save'}
                    </Button>
                </DialogActions>
            </Dialog>
            <Snackbar
                open={!!toast}
                autoHideDuration={3500}
                anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
                onClose={() => setToast(null)}
            >
                {toast ? <Alert severity={toast.type}>{toast.msg}</Alert> : undefined}
            </Snackbar>
        </Box>
    );
}
