import { useMemo, useState } from 'react';
import {
    Box, Tabs, Tab, Stack, Button, Alert, CircularProgress, IconButton, Typography,
    LinearProgress, FormControl, InputLabel, OutlinedInput, InputAdornment, FormHelperText,
    Paper,
} from '@mui/material';
import EmailOutlined from '@mui/icons-material/EmailOutlined';
import PersonOutline from '@mui/icons-material/PersonOutline';
import LockOutlined from '@mui/icons-material/LockOutlined';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import { useNavigate } from 'react-router-dom';

import { api, type PublicUser } from '../../lib/api';
import { createAccountMaterial } from '../../lib/crypto/keys';
import { makeVerifier, deriveKEK } from '../../lib/crypto/argon2';
import { unwrapDEK } from '../../lib/crypto/unwrap';
import { useAuth } from '../../auth/auth-context';
import { useCrypto } from '../../lib/crypto/crypto-context';
import type { Theme } from '@mui/material/styles';

type Mode = 'login' | 'signup';
type Props = { onSuccess?: (user: PublicUser, mp: string) => void; fixedHeight?: boolean };

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
    const [identifier, setIdentifier] = useState('');
    const [username, setUsername] = useState('');
    const [mp, setMp] = useState('');
    const [mp2, setMp2] = useState('');
    const [show, setShow] = useState(false);
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

    const { login } = useAuth();
    const { setDEK, disarm } = useCrypto();
    const navigate = useNavigate();

    const pwdScore = useMemo(() => scorePassword(mp), [mp]);
    const trimmedIdentifier = identifier.trim();
    const trimmedUsername = username.trim();
    const usernameError = mode === 'signup' && !!username && trimmedUsername.length < 4;
    const disabled = busy
        || !trimmedIdentifier
        || !mp
        || (mode === 'signup' && (trimmedUsername.length < 4 || mp !== mp2));
    const identifierLabel = mode === 'login' ? 'Email or Username *' : 'Email *';
    const identifierType = mode === 'login' ? 'text' : 'email';
    const gradientBtn = 'linear-gradient(90deg, #2563eb 0%, #6366f1 50%, #7c3aed 100%)';

    const primaryButtonSx = {
        py: 1.3,
        fontWeight: 800,
        borderRadius: 3,
        background: gradientBtn,
        color: '#fff',
        boxShadow: '0 8px 24px rgba(99,102,241,.25)',
        textTransform: 'none' as const,
        '&:hover': { opacity: 0.95, boxShadow: '0 10px 28px rgba(99,102,241,.35)', background: gradientBtn },
        '&.Mui-disabled': { opacity: 0.5, background: gradientBtn },
    };

    const loginFieldStyles = (theme: Theme) => ({
        flex: 1,
        minWidth: 0,
        '& .MuiOutlinedInput-root': {
            backgroundColor:
                theme.palette.mode === 'dark'
                    ? 'rgba(15,23,42,0.55)'
                    : 'rgba(255,255,255,0.95)',
            borderRadius: 2,
            color: theme.palette.mode === 'dark' ? '#f8fafc' : theme.palette.text.primary,
            boxShadow:
                theme.palette.mode === 'dark'
                    ? '0 8px 24px rgba(15,23,42,0.55)'
                    : '0 10px 26px rgba(99,102,241,0.12)',
            transition: 'background-color .3s ease, box-shadow .3s ease, border-color .3s ease',
            '& fieldset': {
                borderColor:
                    theme.palette.mode === 'dark'
                        ? 'rgba(148,163,184,0.35)'
                        : 'rgba(99,102,241,0.3)',
            },
            '&:hover fieldset': {
                borderColor:
                    theme.palette.mode === 'dark'
                        ? 'rgba(129,140,248,0.65)'
                        : 'rgba(99,102,241,0.6)',
            },
            '&.Mui-focused': {
                boxShadow:
                    theme.palette.mode === 'dark'
                        ? '0 0 0 3px rgba(129,140,248,0.25)'
                        : '0 0 0 3px rgba(99,102,241,0.18)',
            },
            '&.Mui-focused fieldset': {
                borderColor: theme.palette.mode === 'dark' ? '#818cf8' : '#6366f1',
            },
            '& .MuiOutlinedInput-input': {
                color: theme.palette.mode === 'dark' ? '#f8fafc' : theme.palette.text.primary,
            },
            '& .MuiSvgIcon-root': {
                color: theme.palette.mode === 'dark' ? '#c7d2fe' : '#6366f1',
            },
            '& .MuiIconButton-root': {
                color: theme.palette.mode === 'dark' ? '#c7d2fe' : '#6366f1',
            },
        },
        '& .MuiInputLabel-root': {
            color:
                theme.palette.mode === 'dark'
                    ? 'rgba(226,232,240,0.8)'
                    : theme.palette.text.secondary,
            '&.Mui-focused': {
                color: theme.palette.mode === 'dark' ? '#c7d2fe' : '#4f46e5',
            },
        },
        '& .MuiFormHelperText-root': {
            color: theme.palette.mode === 'dark' ? '#e2e8f0' : theme.palette.text.secondary,
        },
    });

    async function handleSubmit() {
        setMsg(null);
        setBusy(true);
        try {
            const trimmedInput = identifier.trim();

            if (mode === 'signup') {
                const normalizedEmail = trimmedInput.toLowerCase();
                const { saltClient, dekEncrypted, dekNonce } = await createAccountMaterial(mp);
                const verifier = await makeVerifier(normalizedEmail, mp, saltClient);
                const normalizedUsername = username.trim();
                await api.register({
                    email: normalizedEmail,
                    username: normalizedUsername,
                    verifier,
                    saltClient,
                    dekEncrypted,
                    dekNonce,
                });
                setMsg({ type: 'success', text: 'Account created. You can log in now.' });
                setMode('login');
                setUsername('');
                setMp('');
                setMp2('');
            } else {
                disarm();

                const { saltClient, email: canonicalEmail } = await api.getSalt(trimmedInput);
                const verifier = await makeVerifier(canonicalEmail, mp, saltClient);
                const data = await api.login({ email: canonicalEmail, verifier });

                login(data.user);

                const kek = await deriveKEK(mp, data.user.saltClient);
                const dek = await unwrapDEK(kek, data.user.dekEncrypted, data.user.dekNonce);
                setDEK(dek);

                onSuccess?.(data.user, mp);
                await Promise.resolve();
                navigate('/dashboard', { replace: true });
            }
        } catch (e: unknown) {
            const message = e instanceof Error ? e.message : 'Something went wrong';
            setMsg({ type: 'error', text: message || 'Something went wrong' });
        } finally {
            setBusy(false);
        }
    }

    const submitOnEnter = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !disabled) handleSubmit();
    };

    return (
        <Box sx={{ width: '100%', maxWidth: mode === 'login' ? 560 : 480, transition: 'max-width .3s ease' }}>
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

            {mode === 'login' ? (
                <Paper
                    elevation={0}
                    sx={(theme) => ({
                        width: '100%',
                        minHeight: fixedHeight ? 340 : 'auto',
                        p: { xs: 3, sm: 4 },
                        borderRadius: 4,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 3,
                        background:
                            theme.palette.mode === 'dark'
                                ? 'linear-gradient(135deg, rgba(15,23,42,0.95) 0%, rgba(30,64,175,0.9) 50%, rgba(99,102,241,0.85) 100%)'
                                : 'linear-gradient(135deg, rgba(59,130,246,0.15) 0%, rgba(129,140,248,0.22) 45%, rgba(20,184,166,0.16) 100%)',
                        border:
                            theme.palette.mode === 'dark'
                                ? '1px solid rgba(148,163,184,0.25)'
                                : '1px solid rgba(99,102,241,0.2)',
                        boxShadow:
                            theme.palette.mode === 'dark'
                                ? '0 18px 42px rgba(15,23,42,0.65)'
                                : '0 22px 45px rgba(79,70,229,0.18)',
                        color: theme.palette.mode === 'dark' ? '#f8fafc' : theme.palette.text.primary,
                        backdropFilter: 'blur(18px)',
                    })}
                >
                    <Stack spacing={3} sx={{ flex: 1 }}>
                        <Box>
                            <Typography
                                variant="overline"
                                sx={{ letterSpacing: 1.5, fontWeight: 700, textTransform: 'uppercase', opacity: 0.8 }}
                            >
                                Welcome back
                            </Typography>
                            <Typography variant="h4" sx={{ fontWeight: 800, mt: 1 }}>
                                Access your vault
                            </Typography>
                            <Typography variant="body2" sx={{ mt: 1.5, maxWidth: 420, opacity: 0.95 }}>
                                Sign in with your email or username and master password to manage your saved credentials
                                securely.
                            </Typography>
                        </Box>

                        <Stack spacing={2.5}>
                            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
                                <FormControl fullWidth variant="outlined" sx={(theme) => loginFieldStyles(theme)}>
                                    <InputLabel htmlFor="identifier">{identifierLabel}</InputLabel>
                                    <OutlinedInput
                                        id="identifier"
                                        type={identifierType}
                                        value={identifier}
                                        onChange={(e) => setIdentifier(e.target.value)}
                                        onKeyDown={submitOnEnter}
                                        startAdornment={
                                            <InputAdornment position="start">
                                                <EmailOutlined fontSize="small" />
                                            </InputAdornment>
                                        }
                                        label={identifierLabel}
                                    />
                                </FormControl>

                                <FormControl fullWidth variant="outlined" sx={(theme) => loginFieldStyles(theme)}>
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
                            </Stack>
                        </Stack>

                        <Stack spacing={2} alignItems={{ sm: 'flex-start' }}>
                            <Button
                                onClick={handleSubmit}
                                disabled={disabled}
                                sx={{
                                    ...primaryButtonSx,
                                    alignSelf: { xs: 'stretch', sm: 'flex-start' },
                                    width: { xs: '100%', sm: 'auto' },
                                    px: { sm: 4 },
                                }}
                                variant="contained"
                            >
                                {busy ? (
                                    <CircularProgress size={22} sx={{ color: '#fff' }} />
                                ) : (
                                    'LOG IN'
                                )}
                            </Button>

                            {msg && (
                                <Alert
                                    severity={msg.type}
                                    variant="filled"
                                    sx={(theme) => ({
                                        borderRadius: 2,
                                        boxShadow:
                                            theme.palette.mode === 'dark'
                                                ? '0 12px 28px rgba(15,23,42,0.5)'
                                                : '0 12px 28px rgba(99,102,241,0.2)',
                                        backgroundColor:
                                            msg.type === 'error'
                                                ? theme.palette.mode === 'dark'
                                                    ? 'rgba(248,113,113,0.9)'
                                                    : 'rgba(239,68,68,0.85)'
                                                : theme.palette.mode === 'dark'
                                                    ? 'rgba(34,197,94,0.85)'
                                                    : 'rgba(34,197,94,0.82)',
                                        color: '#fff',
                                    })}
                                >
                                    {msg.text}
                                </Alert>
                            )}
                        </Stack>
                    </Stack>
                </Paper>
            ) : (
                <Stack spacing={2} sx={{ minHeight: fixedHeight ? 340 : 'auto' }}>
                    <FormControl fullWidth variant="outlined">
                        <InputLabel htmlFor="identifier">{identifierLabel}</InputLabel>
                        <OutlinedInput
                            id="identifier"
                            type={identifierType}
                            value={identifier}
                            onChange={(e) => setIdentifier(e.target.value)}
                            onKeyDown={submitOnEnter}
                            startAdornment={
                                <InputAdornment position="start">
                                    <EmailOutlined fontSize="small" />
                                </InputAdornment>
                            }
                            label={identifierLabel}
                        />
                    </FormControl>

                    {mode === 'signup' ? (
                        <FormControl fullWidth variant="outlined" error={usernameError}>
                            <InputLabel htmlFor="username">Username *</InputLabel>
                            <OutlinedInput
                                id="username"
                                type="text"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                onKeyDown={submitOnEnter}
                                startAdornment={
                                    <InputAdornment position="start">
                                        <PersonOutline fontSize="small" />
                                    </InputAdornment>
                                }
                                label="Username *"
                            />
                            <FormHelperText>
                                {usernameError ? 'Username must be at least 4 characters long' : ' '}
                            </FormHelperText>
                        </FormControl>
                    ) : (
                        fixedHeight && (
                            <FormControl fullWidth variant="outlined" sx={{ opacity: 0 }}>
                                <InputLabel htmlFor="username-hidden">Username *</InputLabel>
                                <OutlinedInput id="username-hidden" label="Username *" />
                                <FormHelperText> </FormHelperText>
                            </FormControl>
                        )
                    )}

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

                    <Button onClick={handleSubmit} disabled={disabled} sx={primaryButtonSx} variant="contained" fullWidth>
                        {busy ? (
                            <CircularProgress size={22} sx={{ color: '#fff' }} />
                        ) : (
                            mode === 'login' ? 'LOG IN' : 'CREATE ACCOUNT'
                        )}
                    </Button>

                    {msg && <Alert severity={msg.type}>{msg.text}</Alert>}
                </Stack>
            )}
        </Box>
    );
}
