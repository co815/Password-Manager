import { useMemo, useState } from 'react';
import {
    Alert,
    Box,
    Button,
    CircularProgress,
    FormControl,
    IconButton,
    InputAdornment,
    InputLabel,
    OutlinedInput,
    Stack,
    Typography,
} from '@mui/material';
import type { Theme } from '@mui/material/styles';
import EmailOutlined from '@mui/icons-material/EmailOutlined';
import LockOutlined from '@mui/icons-material/LockOutlined';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import { useNavigate } from 'react-router-dom';

import { api, primeCsrfToken, type PublicUser } from '../../lib/api';
import { makeVerifier, deriveKEK } from '../../lib/crypto/argon2';
import { unwrapDEK } from '../../lib/crypto/unwrap';
import { useAuth } from '../../auth/auth-context';
import { useCrypto } from '../../lib/crypto/crypto-context';

const gradientBtn = 'linear-gradient(90deg, #2563eb 0%, #6366f1 50%, #7c3aed 100%)';

const fieldStyles = (theme: Theme) => ({
    '& .MuiOutlinedInput-root': {
        backgroundColor:
            theme.palette.mode === 'dark' ? 'rgba(15,23,42,0.55)' : 'rgba(255,255,255,0.92)',
        borderRadius: 2.5,
        color: theme.palette.mode === 'dark' ? '#f8fafc' : theme.palette.text.primary,
        boxShadow:
            theme.palette.mode === 'dark'
                ? '0 10px 30px rgba(15,23,42,0.55)'
                : '0 18px 38px rgba(79,70,229,0.18)',
        '& fieldset': {
            borderColor:
                theme.palette.mode === 'dark' ? 'rgba(148,163,184,0.45)' : 'rgba(125,140,255,0.4)',
        },
        '&:hover fieldset': {
            borderColor: theme.palette.mode === 'dark' ? 'rgba(129,140,248,0.75)' : 'rgba(99,102,241,0.7)',
        },
        '&.Mui-focused': {
            boxShadow:
                theme.palette.mode === 'dark'
                    ? '0 0 0 3px rgba(129,140,248,0.28)'
                    : '0 0 0 3px rgba(79,70,229,0.22)',
        },
        '&.Mui-focused fieldset': {
            borderColor: theme.palette.mode === 'dark' ? '#a5b4fc' : '#6366f1',
        },
        '& .MuiOutlinedInput-input': {
            color: theme.palette.mode === 'dark' ? '#f8fafc' : theme.palette.text.primary,
            fontWeight: 500,
        },
        '& .MuiSvgIcon-root': {
            color: theme.palette.mode === 'dark' ? '#c7d2fe' : '#4f46e5',
        },
        '& .MuiIconButton-root': {
            color: theme.palette.mode === 'dark' ? '#c7d2fe' : '#4f46e5',
        },
    },
    '& .MuiInputLabel-root': {
        color: theme.palette.mode === 'dark' ? 'rgba(226,232,240,0.75)' : 'rgba(30,41,59,0.7)',
        '&.Mui-focused': {
            color: theme.palette.mode === 'dark' ? '#c7d2fe' : '#4338ca',
        },
        fontWeight: 500,
    },
});

type Props = {
    onSuccess?: (user: PublicUser, mp: string) => void;
    onSwitchToSignup?: () => void;
};

export default function LoginCard({ onSuccess, onSwitchToSignup }: Props) {
    const [identifier, setIdentifier] = useState('');
    const [mp, setMp] = useState('');
    const [show, setShow] = useState(false);
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

    const { login } = useAuth();
    const { setDEK, disarm, lockNow } = useCrypto();
    const navigate = useNavigate();

    const trimmedIdentifier = useMemo(() => identifier.trim(), [identifier]);
    const disabled = busy || !trimmedIdentifier || !mp;

    async function handleSubmit() {
        if (disabled) return;
        setMsg(null);
        setBusy(true);
        try {
            lockNow();
            disarm();

            const { saltClient, email: canonicalEmail } = await api.getSalt(trimmedIdentifier);
            const verifier = await makeVerifier(canonicalEmail, mp, saltClient);
            await primeCsrfToken();
            const data = await api.login({ email: canonicalEmail, verifier });

            login(data.user);

            const kek = await deriveKEK(mp, data.user.saltClient);
            const dek = await unwrapDEK(kek, data.user.dekEncrypted, data.user.dekNonce);
            setDEK(dek);

            await primeCsrfToken();
            onSuccess?.(data.user, mp);
            await Promise.resolve();
            navigate('/dashboard', { replace: true });
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
        <Box
            sx={(theme) => ({
                width: '100%',
                maxWidth: { xs: 460, sm: 520 },
                mx: 'auto',
                p: { xs: 3, sm: 4 },
                borderRadius: 4,
                background:
                    theme.palette.mode === 'dark'
                        ? 'linear-gradient(135deg, rgba(15,23,42,0.92) 0%, rgba(30,64,175,0.88) 45%, rgba(99,102,241,0.85) 100%)'
                        : 'linear-gradient(135deg, rgba(79,70,229,0.95) 0%, rgba(37,99,235,0.92) 45%, rgba(6,182,212,0.9) 100%)',
                color: '#f8fafc',
                boxShadow:
                    theme.palette.mode === 'dark'
                        ? '0 22px 48px rgba(15,23,42,0.65)'
                        : '0 26px 52px rgba(37,99,235,0.28)',
                backdropFilter: 'blur(20px)',
            })}
        >
            <Stack spacing={3}>
                <Stack spacing={1}>
                    <Typography variant="overline" sx={{ letterSpacing: 1.6, fontWeight: 700, opacity: 0.85 }}>
                        Welcome back
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 800, lineHeight: 1.1 }}>
                        Access your vault
                    </Typography>
                    <Typography variant="body2" sx={{ opacity: 0.9 }}>
                        Sign in with your email or username and master password to manage your credentials securely.
                    </Typography>
                </Stack>

                <Stack spacing={2}>
                    <FormControl fullWidth variant="outlined" sx={(theme) => fieldStyles(theme)}>
                        <InputLabel htmlFor="login-identifier">Email or Username *</InputLabel>
                        <OutlinedInput
                            id="login-identifier"
                            type="text"
                            value={identifier}
                            onChange={(e) => setIdentifier(e.target.value)}
                            onKeyDown={submitOnEnter}
                            startAdornment={
                                <InputAdornment position="start">
                                    <EmailOutlined fontSize="small" />
                                </InputAdornment>
                            }
                            label="Email or Username *"
                        />
                    </FormControl>

                    <FormControl fullWidth variant="outlined" sx={(theme) => fieldStyles(theme)}>
                        <InputLabel htmlFor="login-password">Master Password *</InputLabel>
                        <OutlinedInput
                            id="login-password"
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
                            label="Master Password *"
                        />
                    </FormControl>
                </Stack>

                <Stack spacing={2}>
                    <Button
                        onClick={handleSubmit}
                        disabled={disabled}
                        sx={{
                            py: 1.25,
                            borderRadius: 3,
                            fontWeight: 800,
                            textTransform: 'none',
                            background: gradientBtn,
                            color: '#fff',
                            boxShadow: '0 14px 32px rgba(99,102,241,0.35)',
                            '&:hover': { background: gradientBtn, opacity: 0.95 },
                            '&.Mui-disabled': { background: gradientBtn, opacity: 0.55 },
                        }}
                        variant="contained"
                    >
                        {busy ? <CircularProgress size={22} sx={{ color: '#fff' }} /> : 'Log in'}
                    </Button>

                    {msg && (
                        <Alert
                            severity={msg.type}
                            variant="filled"
                            sx={{
                                borderRadius: 2,
                                backgroundColor: msg.type === 'error' ? 'rgba(248,113,113,0.85)' : 'rgba(34,197,94,0.85)',
                                color: '#fff',
                                boxShadow: '0 16px 34px rgba(15,23,42,0.55)',
                            }}
                        >
                            {msg.text}
                        </Alert>
                    )}

                    <Stack direction="row" spacing={1} justifyContent="center" alignItems="center">
                        <Typography
                            variant="body2"
                            sx={{ opacity: 0.85, display: 'flex', alignItems: 'center' }}
                        >
                            Need an account?
                        </Typography>
                        <Button
                            onClick={onSwitchToSignup}
                            color="inherit"
                            size="small"
                            sx={{ textTransform: 'none', fontWeight: 700, px: 0, minWidth: 0 }}
                        >
                            Sign up
                        </Button>
                    </Stack>
                </Stack>
            </Stack>
        </Box>
    );
}