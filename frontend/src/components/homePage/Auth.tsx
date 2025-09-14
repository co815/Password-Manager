import { useState } from 'react';
import {
    Box, Tabs, Tab, Stack, TextField, Button, Alert, CircularProgress, Typography
} from '@mui/material';
import { api } from '../../lib/api';
import { createAccountMaterial } from '../../lib/crypto/keys';
import { makeVerifier } from '../../lib/crypto/argon2';

type Mode = 'login' | 'signup';
type Props = { onSuccess?: (token: string, user: any, masterPassword: string) => void };

export default function Auth({ onSuccess }: Props) {
    const [mode, setMode] = useState<Mode>('login');
    const [email, setEmail] = useState('');
    const [mp, setMp] = useState('');
    const [mp2, setMp2] = useState('');
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<{ type: 'success'|'error', text: string } | null>(null);

    const disabled = busy || !email || !mp || (mode === 'signup' && mp !== mp2);

    async function handleSubmit() {
        setMsg(null); setBusy(true);
        try {
            if (mode === 'signup') {
                const { saltClient, dekEncrypted, dekNonce } = await createAccountMaterial(mp);
                const verifier = await makeVerifier(email, mp, saltClient);
                await api.register({ email, verifier, saltClient, dekEncrypted, dekNonce });
                setMsg({ type: 'success', text: 'Account created. You can log in now.' });
                setMode('login');
            } else {
                const { saltClient } = await api.getSalt(email);
                const verifier = await makeVerifier(email, mp, saltClient);
                const data = await api.login({ email, verifier });
                localStorage.setItem('token', data.accessToken);
                localStorage.setItem('profile', JSON.stringify(data.user));
                setMsg({ type: 'success', text: 'Logged in!' });
                onSuccess?.(data.accessToken, data.user, mp);
            }
        } catch (e: any) {
            setMsg({ type: 'error', text: e?.message || 'Something went wrong' });
        } finally { setBusy(false); }
    }

    return (
        <Box sx={{ width: '100%', maxWidth: 380 }}>
            <Typography variant="h6" sx={{ textAlign: 'center', mb: 1, letterSpacing: 1, fontWeight: 700 }}>
                {mode === 'login' ? 'LOG IN' : 'SIGN UP'}
            </Typography>

            {/* Tabs ca în screenshot (sus: Log in | Sign up) */}
            <Tabs
                value={mode}
                onChange={(_, v) => setMode(v)}
                centered
                sx={{
                    mb: 2,
                    '& .MuiTabs-indicator': { height: 3, borderRadius: 2 },
                    '& .MuiTab-root': { fontWeight: 600 }
                }}
            >
                <Tab value="login" label="LOG IN" />
                <Tab value="signup" label="SIGN UP" />
            </Tabs>

            {/* Form */}
            <Stack spacing={2}>
                <TextField
                    label="Email *" type="email" value={email}
                    onChange={e => setEmail(e.target.value)} fullWidth
                />
                <TextField
                    label="Password *" type="password" value={mp}
                    onChange={e => setMp(e.target.value)} fullWidth
                />
                {mode === 'signup' && (
                    <TextField
                        label="Confirm Password *" type="password" value={mp2}
                        onChange={e => setMp2(e.target.value)} fullWidth
                        error={!!mp2 && mp2 !== mp}
                        helperText={mp2 && mp2 !== mp ? 'Passwords do not match' : ' '}
                    />
                )}

                <Button
                    onClick={handleSubmit} disabled={disabled}
                    sx={{
                        py: 1.2,
                        fontWeight: 700,
                        borderRadius: 2,
                        background: 'linear-gradient(90deg, #2563eb 0%, #6366f1 50%, #7c3aed 100%)',
                        color: '#fff',
                        '&:hover': { opacity: 0.95, background: 'linear-gradient(90deg, #1d4ed8 0%, #4f46e5 50%, #6d28d9 100%)' }
                    }}
                    variant="contained"
                >
                    {busy ? <CircularProgress size={22} sx={{ color: '#fff' }}/> : (mode === 'login' ? 'LOG IN' : 'CREATE ACCOUNT')}
                </Button>

                {msg && <Alert severity={msg.type}>{msg.text}</Alert>}
            </Stack>
        </Box>
    );
}
