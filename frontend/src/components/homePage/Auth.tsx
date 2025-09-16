import { useMemo, useState } from 'react';
import {
    Box, Tabs, Tab, Stack, Button, Alert, CircularProgress, IconButton, Typography,
    LinearProgress, FormControl, InputLabel, OutlinedInput, InputAdornment, FormHelperText,
} from '@mui/material';
import EmailOutlined from '@mui/icons-material/EmailOutlined';
import LockOutlined from '@mui/icons-material/LockOutlined';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import { useNavigate } from 'react-router-dom';

import { api } from '../../lib/api';
import { createAccountMaterial } from '../../lib/crypto/keys';
import { makeVerifier, deriveKEK } from '../../lib/crypto/argon2';
import { unwrapDEK } from '../../lib/crypto/unwrap';
import { useAuth } from '../../auth/AuthContext';
import { useCrypto } from '../../lib/crypto/CryptoContext';

type Mode = 'login' | 'signup';
type Props = { onSuccess?: (token: string, user: any, mp: string) => void; fixedHeight?: boolean };

function scorePassword(p: string) {
    let s = 0;
    if (p.length >= 8) s++;
    if (/[A-Z]/.test(p)) s++;
    if (/[a-z]/.test(p)) s++;
    if (/\d/.test(p)) s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;
    return Math.min(s, 5);
}

export default function Auth({ onSuccess, fixedHeight }: Props) {
    const [mode, setMode] = useState<Mode>('login');
    const [email, setEmail] = useState('');
    const [mp, setMp] = useState('');
    const [mp2, setMp2] = useState('');
    const [show, setShow] = useState(false);
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

    const { login } = useAuth();
    const { setDEK, disarm } = useCrypto();
    const navigate = useNavigate();

    const pwdScore = useMemo(() => scorePassword(mp), [mp]);
    const disabled = busy || !email || !mp || (mode === 'signup' && mp !== mp2);
    const gradientBtn = 'linear-gradient(90deg, #2563eb 0%, #6366f1 50%, #7c3aed 100%)';

    async function handleSubmit() {
        setMsg(null);
        setBusy(true);
        try {
            const normalizedEmail = email.trim().toLowerCase();

            if (mode === 'signup') {
                const { saltClient, dekEncrypted, dekNonce } = await createAccountMaterial(mp);
                const verifier = await makeVerifier(normalizedEmail, mp, saltClient);
                await api.register({ email: normalizedEmail, verifier, saltClient, dekEncrypted, dekNonce });
                setMsg({ type: 'success', text: 'Account created. You can log in now.' });
                setMode('login');
                setMp('');
                setMp2('');
            } else {
                disarm();

                const { saltClient } = await api.getSalt(normalizedEmail);
                const verifier = await makeVerifier(normalizedEmail, mp, saltClient);
                const data = await api.login({ email: normalizedEmail, verifier });

                login(data.accessToken, data.user);

                const kek = await deriveKEK(mp, data.user.saltClient);
                const dek = await unwrapDEK(kek, data.user.dekEncrypted, data.user.dekNonce);
                setDEK(dek);

                onSuccess?.(data.accessToken, data.user, mp);
                await Promise.resolve();
                navigate('/dashboard', { replace: true });
            }
        } catch (e: any) {
            setMsg({ type: 'error', text: e?.message || 'Something went wrong' });
        } finally {
            setBusy(false);
        }
    }

    const submitOnEnter = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !disabled) handleSubmit();
    };

    return (
        <Box sx={{ width: '100%', maxWidth: 480 }}>
            <Typography variant="h6" textAlign="center" fontWeight={800} letterSpacing={1} mb={1}>
                {mode === 'login' ? 'LOG IN' : 'SIGN UP'}
            </Typography>

            <Tabs
                value={mode}
                onChange={(_, v) => setMode(v as Mode)}
                centered
                sx={{
                    mb: 2,
                    '& .MuiTabs-indicator': { height: 4, borderRadius: 2, background: gradientBtn },
                    '& .MuiTab-root': { fontWeight: 700, color: 'text.secondary', '&.Mui-selected': { color: 'text.primary' } },
                }}
            >
                <Tab value="login" label="LOG IN" />
                <Tab value="signup" label="SIGN UP" />
            </Tabs>

            <Stack spacing={2} sx={{ minHeight: fixedHeight ? 340 : 'auto' }}>
                <FormControl fullWidth variant="outlined">
                    <InputLabel htmlFor="email">Email *</InputLabel>
                    <OutlinedInput
                        id="email"
                        type="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        onKeyDown={submitOnEnter}
                        startAdornment={
                            <InputAdornment position="start">
                                <EmailOutlined fontSize="small" />
                            </InputAdornment>
                        }
                        label="Email *"
                    />
                </FormControl>

                <FormControl fullWidth variant="outlined">
                    <InputLabel htmlFor="password">Password *</InputLabel>
                    <OutlinedInput
                        id="password"
                        type={show ? 'text' : 'password'}
                        value={mp}
                        onChange={(e) => setMp(e.target.value)}
                        onKeyDown={submitOnEnter}
                        startAdornment={
                            <InputAdornment position="start">
                                <LockOutlined fontSize="small" />
                            </InputAdornment>
                        }
                        endAdornment={
                            <InputAdornment position="end">
                                <IconButton onClick={() => setShow((s) => !s)} edge="end" aria-label="toggle password visibility">
                                    {show ? <VisibilityOff /> : <Visibility />}
                                </IconButton>
                            </InputAdornment>
                        }
                        label="Password *"
                    />
                </FormControl>

                {mode === 'signup' ? (
                    <>
                        <LinearProgress
                            variant="determinate"
                            value={(pwdScore / 5) * 100}
                            sx={{
                                height: 6,
                                borderRadius: 3,
                                mx: 0.5,
                                '& .MuiLinearProgress-bar': {
                                    background: ['#ef4444', '#f59e0b', '#10b981', '#22c55e', '#16a34a'][Math.max(0, pwdScore - 1)],
                                },
                            }}
                        />
                        <FormControl fullWidth variant="outlined" error={!!mp2 && mp2 !== mp}>
                            <InputLabel htmlFor="confirm">Confirm Password *</InputLabel>
                            <OutlinedInput
                                id="confirm"
                                type={show ? 'text' : 'password'}
                                value={mp2}
                                onChange={(e) => setMp2(e.target.value)}
                                onKeyDown={submitOnEnter}
                                label="Confirm Password *"
                            />
                            <FormHelperText>{mp2 && mp2 !== mp ? 'Passwords do not match' : ' '}</FormHelperText>
                        </FormControl>
                    </>
                ) : (
                    fixedHeight && (
                        <>
                            <Box sx={{ height: 6, borderRadius: 3, opacity: 0 }} />
                            <FormControl fullWidth variant="outlined" sx={{ opacity: 0 }}>
                                <InputLabel htmlFor="confirm-hidden">Confirm Password *</InputLabel>
                                <OutlinedInput id="confirm-hidden" label="Confirm Password *" />
                                <FormHelperText> </FormHelperText>
                            </FormControl>
                        </>
                    )
                )}

                <Button
                    onClick={handleSubmit}
                    disabled={disabled}
                    sx={{
                        py: 1.3,
                        fontWeight: 800,
                        borderRadius: 3,
                        background: gradientBtn,
                        color: '#fff',
                        boxShadow: '0 8px 24px rgba(99,102,241,.25)',
                        '&:hover': { opacity: 0.95, boxShadow: '0 10px 28px rgba(99,102,241,.35)', background: gradientBtn },
                        '&.Mui-disabled': { opacity: 0.5, background: gradientBtn },
                    }}
                    variant="contained"
                    fullWidth
                >
                    {busy ? <CircularProgress size={22} sx={{ color: '#fff' }} /> : mode === 'login' ? 'LOG IN' : 'CREATE ACCOUNT'}
                </Button>

                {msg && <Alert severity={msg.type}>{msg.text}</Alert>}
            </Stack>
        </Box>
    );
}
