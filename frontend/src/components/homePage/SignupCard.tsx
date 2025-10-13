import {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import type {KeyboardEvent} from 'react';
import {
    Alert,
    Box,
    Button,
    CircularProgress,
    FormControl,
    FormHelperText,
    IconButton,
    InputAdornment,
    InputLabel,
    LinearProgress,
    OutlinedInput,
    Stack,
    Typography,
} from '@mui/material';
import {useTheme, type Theme} from '@mui/material/styles';
import EmailOutlined from '@mui/icons-material/EmailOutlined';
import PersonOutline from '@mui/icons-material/PersonOutline';
import LockOutlined from '@mui/icons-material/LockOutlined';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';

import {ApiError, api, primeCsrfToken} from '../../lib/api';
import {createAccountMaterial} from '../../lib/crypto/keys';
import {makeVerifier} from '../../lib/crypto/argon2';
import useCaptchaConfig from '../../lib/hooks/useCaptchaConfig';
import CaptchaChallenge, {type CaptchaHandle} from './CaptchaChallenge';

const gradientBtn = 'linear-gradient(90deg, #2563eb 0%, #6366f1 50%, #7c3aed 100%)';

const fieldStyles = (theme: Theme) => ({
    '& .MuiOutlinedInput-root': {
        backgroundColor:
            theme.palette.mode === 'dark' ? 'rgba(15,23,42,0.55)' : 'rgba(255,255,255,0.94)',
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
    onSwitchToLogin?: () => void;
};

function scorePassword(p: string) {
    let score = 0;
    if (p.length >= 8) score++;
    if (/[A-Z]/.test(p)) score++;
    if (/[a-z]/.test(p)) score++;
    if (/\d/.test(p)) score++;
    if (/[^A-Za-z0-9]/.test(p)) score++;
    return Math.min(score, 5);
}

export default function SignupCard({onSwitchToLogin}: Props) {
    const [email, setEmail] = useState('');
    const [username, setUsername] = useState('');
    const [mp, setMp] = useState('');
    const [mp2, setMp2] = useState('');
    const [show, setShow] = useState(false);
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
    const [captchaToken, setCaptchaToken] = useState<string | null>(null);
    const [captchaError, setCaptchaError] = useState<string | null>(null);
    const captchaRef = useRef<CaptchaHandle | null>(null);
    const missingKeyLoggedRef = useRef(false);
    const them = useTheme();
    const captchaTheme = them.palette.mode === 'dark' ? 'dark' : 'light';

    const trimmedEmail = useMemo(() => email.trim().toLowerCase(), [email]);
    const trimmedUsername = useMemo(() => username.trim(), [username]);
    const pwdScore = useMemo(() => scorePassword(mp), [mp]);
    const usernameError = !!trimmedUsername && trimmedUsername.length < 4;
    const confirmError = !!mp2 && mp2 !== mp;
    const {
        config: captchaConfig,
        loading: captchaLoading,
        error: captchaConfigError,
        refresh: reloadCaptchaConfig,
    } = useCaptchaConfig();
    const rawCaptchaProvider = captchaConfig?.provider ?? 'NONE';
    const hasSiteKey = Boolean(captchaConfig?.siteKey && captchaConfig.siteKey.trim());
    const captchaEnabled = Boolean(
        captchaConfig?.enabled
        && rawCaptchaProvider === 'RECAPTCHA'
        && hasSiteKey
    );
    const siteKey = captchaEnabled ? captchaConfig?.siteKey ?? '' : '';
    const captchaProvider = captchaEnabled ? rawCaptchaProvider : 'NONE';
    const disabled =
        busy
        || captchaLoading
        || Boolean(captchaConfigError)
        || !trimmedEmail
        || !trimmedUsername
        || trimmedUsername.length < 4
        || !mp
        || mp !== mp2
        || (captchaEnabled && !captchaToken);

    const handleSwitchToLogin = useCallback(() => {
        setMsg(null);
        if (captchaEnabled) {
            captchaRef.current?.reset();
            setCaptchaToken(null);
            setCaptchaError(null);
        }
        onSwitchToLogin?.();
    }, [captchaEnabled, onSwitchToLogin]);

    useEffect(() => {
        if (msg?.type === 'success') {
            const timer = setTimeout(() => {
                handleSwitchToLogin();
            }, 1800);
            return () => clearTimeout(timer);
        }
        return undefined;
    }, [handleSwitchToLogin, msg]);

    useEffect(() => {
        if (!captchaConfig || captchaLoading) {
            return;
        }
        if (captchaConfig.provider === 'RECAPTCHA' && !hasSiteKey && !missingKeyLoggedRef.current) {
            missingKeyLoggedRef.current = true;
            console.error('[CAPTCHA] Missing site key for provider %s. Check RECAPTCHA_SITE_KEY or backend configuration.', captchaConfig.provider);
        }
    }, [captchaConfig, captchaLoading, hasSiteKey]);

    async function handleSubmit() {
        if (disabled) {
            if (captchaEnabled && !captchaToken) {
                setCaptchaError('Please complete the CAPTCHA challenge.');
            }
            return;
        }
        setMsg(null);
        setBusy(true);
        try {
            const {saltClient, dekEncrypted, dekNonce} = await createAccountMaterial(mp);
            const verifier = await makeVerifier(trimmedEmail, mp, saltClient);
            await primeCsrfToken();
            await api.register({
                email: trimmedEmail,
                username: trimmedUsername,
                verifier,
                saltClient,
                dekEncrypted,
                dekNonce,
                ...(captchaEnabled ? {captchaToken} : {}),
            });
            setMsg({type: 'success', text: 'Account created successfully! Redirecting to login…'});
            setUsername('');
            setEmail('');
            setMp('');
            setMp2('');
            if (captchaEnabled) {
                captchaRef.current?.reset();
                setCaptchaToken(null);
                setCaptchaError(null);
            }
        } catch (e: unknown) {
            if (e instanceof ApiError) {
                const message = typeof e.message === 'string' ? e.message : '';
                const details = typeof e.data === 'object' && e.data && 'message' in e.data
                    ? String((e.data as { message?: unknown }).message ?? '')
                    : '';
                const errorCode = typeof e.data === 'object' && e.data && 'error' in e.data
                    ? String((e.data as { error?: unknown }).error ?? '')
                    : '';
                const normalized = (message || details || '').trim();
                if (e.status === 400 && errorCode === 'INVALID_CAPTCHA') {
                    console.warn('[CAPTCHA] Signup rejected due to invalid token.');
                    setCaptchaError('CAPTCHA verification failed. Please try again.');
                    setMsg({type: 'error', text: 'CAPTCHA verification failed. Please try again.'});
                } else {
                    setMsg({type: 'error', text: normalized || 'Something went wrong'});
                }
            } else {
                const message = e instanceof Error ? e.message : 'Something went wrong';
                setMsg({type: 'error', text: message || 'Something went wrong'});
            }
        } finally {
            if (captchaEnabled) {
                captchaRef.current?.reset();
                setCaptchaToken(null);
            }
            setBusy(false);
        }
    }

    const submitOnEnter = (e: KeyboardEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        if (e.key === 'Enter' && !disabled) handleSubmit();
    };

    return (
        <Box
            sx={(theme) => ({
                width: '100%',
                maxWidth: {xs: 600, sm: 600},
                mx: 'auto',
                p: {xs: 3, sm: 4},
                borderRadius: 4,
                background:
                    theme.palette.mode === 'dark'
                        ? 'linear-gradient(135deg, rgba(15,23,42,0.9) 0%, rgba(76,29,149,0.85) 45%, rgba(129,140,248,0.82) 100%)'
                        : 'linear-gradient(135deg, rgba(129,140,248,0.95) 0%, rgba(59,130,246,0.9) 45%, rgba(6,182,212,0.9) 100%)',
                color: '#f8fafc',
                boxShadow:
                    theme.palette.mode === 'dark'
                        ? '0 24px 52px rgba(15,23,42,0.65)'
                        : '0 28px 56px rgba(79,70,229,0.28)',
                backdropFilter: 'blur(20px)',
            })}
        >
            <Stack spacing={3}>
                <Stack spacing={1}>
                    <Typography variant="overline" sx={{letterSpacing: 1.6, fontWeight: 700, opacity: 0.85}}>
                        Create your vault
                    </Typography>
                    <Typography variant="h4" sx={{fontWeight: 800, lineHeight: 1.1}}>
                        Join Password Manager
                    </Typography>
                    <Typography variant="body2" sx={{opacity: 0.9}}>
                        Choose a username and a strong master password to keep your secrets safe.
                    </Typography>
                </Stack>

                <Stack spacing={2}>
                    <FormControl fullWidth variant="outlined" sx={(theme) => fieldStyles(theme)}>
                        <InputLabel htmlFor="signup-email">Email *</InputLabel>
                        <OutlinedInput
                            id="signup-email"
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            onKeyDown={submitOnEnter}
                            startAdornment={
                                <InputAdornment position="start">
                                    <EmailOutlined fontSize="small"/>
                                </InputAdornment>
                            }
                            label="Email *"
                        />
                    </FormControl>

                    <FormControl fullWidth variant="outlined" error={usernameError} sx={(theme) => fieldStyles(theme)}>
                        <InputLabel htmlFor="signup-username">Username *</InputLabel>
                        <OutlinedInput
                            id="signup-username"
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            onKeyDown={submitOnEnter}
                            startAdornment={
                                <InputAdornment position="start">
                                    <PersonOutline fontSize="small"/>
                                </InputAdornment>
                            }
                            label="Username *"
                        />
                        <FormHelperText>
                            {usernameError ? 'Username must be at least 4 characters long' : ' '}
                        </FormHelperText>
                    </FormControl>

                    <FormControl fullWidth variant="outlined" sx={(theme) => fieldStyles(theme)}>
                        <InputLabel htmlFor="signup-password">Master Password *</InputLabel>
                        <OutlinedInput
                            id="signup-password"
                            type={show ? 'text' : 'password'}
                            value={mp}
                            onChange={(e) => setMp(e.target.value)}
                            onKeyDown={submitOnEnter}
                            startAdornment={
                                <InputAdornment position="start">
                                    <LockOutlined fontSize="small"/>
                                </InputAdornment>
                            }
                            endAdornment={
                                <InputAdornment position="end">
                                    <IconButton onClick={() => setShow((s) => !s)} edge="end"
                                                aria-label="toggle password visibility">
                                        {show ? <VisibilityOff/> : <Visibility/>}
                                    </IconButton>
                                </InputAdornment>
                            }
                            label="Master Password *"
                        />
                    </FormControl>

                    <LinearProgress
                        variant="determinate"
                        value={(pwdScore / 5) * 100}
                        sx={{
                            height: 6,
                            borderRadius: 3,
                            mx: 0.5,
                            '& .MuiLinearProgress-bar': {
                                background: ['#ef4444', '#f97316', '#facc15', '#22c55e', '#16a34a'][Math.max(0, pwdScore - 1)],
                            },
                            backgroundColor: 'rgba(148,163,184,0.35)',
                        }}
                    />

                    <FormControl fullWidth variant="outlined" error={confirmError} sx={(theme) => fieldStyles(theme)}>
                        <InputLabel htmlFor="signup-confirm">Confirm Password *</InputLabel>
                        <OutlinedInput
                            id="signup-confirm"
                            type={show ? 'text' : 'password'}
                            value={mp2}
                            onChange={(e) => setMp2(e.target.value)}
                            onKeyDown={submitOnEnter}
                            label="Confirm Password *"
                        />
                        <FormHelperText>{confirmError ? 'Passwords do not match' : ' '}</FormHelperText>
                    </FormControl>
                    {captchaLoading ? (
                        <Stack spacing={1} alignItems="center">
                            <CircularProgress size={32} color="inherit"/>
                            <Typography variant="body2" sx={{opacity: 0.85}}>
                                Preparing CAPTCHA challenge…
                            </Typography>
                        </Stack>
                    ) : null}
                    {captchaConfigError ? (
                        <Alert
                            severity="error"
                            action={(
                                <Button
                                    color="inherit"
                                    size="small"
                                    onClick={() => {
                                        reloadCaptchaConfig().catch(() => undefined);
                                    }}
                                    disabled={captchaLoading}
                                >
                                    Retry
                                </Button>
                            )}
                        >
                            Unable to load the CAPTCHA challenge. Please try again.
                        </Alert>
                    ) : null}
                    {captchaEnabled ? (
                        <Stack spacing={1} alignItems="center">
                            <CaptchaChallenge
                                ref={captchaRef}
                                provider={captchaProvider}
                                siteKey={siteKey}
                                theme={captchaTheme}
                                onChange={(token) => {
                                    setCaptchaToken(token ?? null);
                                    if (token) setCaptchaError(null);
                                }}
                                onExpired={() => {
                                    setCaptchaToken(null);
                                    setCaptchaError('The CAPTCHA challenge expired. Please try again.');
                                }}
                                onErrored={(message) => {
                                    setCaptchaToken(null);
                                    setCaptchaError(message
                                        ?? 'Unable to load the CAPTCHA challenge. Please try again.'
                                    );
                                }}
                            />
                            {captchaError ? (
                                <FormHelperText error>{captchaError}</FormHelperText>
                            ) : null}
                        </Stack>
                    ) : null}
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
                            boxShadow: '0 14px 32px rgba(129,140,248,0.38)',
                            '&:hover': {background: gradientBtn, opacity: 0.95},
                            '&.Mui-disabled': {background: gradientBtn, opacity: 0.55},
                        }}
                        variant="contained"
                    >
                        {busy ? <CircularProgress size={22} sx={{color: '#fff'}}/> : 'Create account'}
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
                            sx={{opacity: 0.85, display: 'flex', alignItems: 'center'}}
                        >
                            Already have an account?
                        </Typography>
                        <Button
                            onClick={handleSwitchToLogin}
                            color="inherit"
                            size="small"
                            sx={{textTransform: 'none', fontWeight: 700, px: 0, minWidth: 0}}
                        >
                            Log in
                        </Button>
                    </Stack>
                </Stack>
            </Stack>
        </Box>
    );
}