import {useEffect, useMemo, useRef, useState} from 'react';
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
    OutlinedInput,
    Stack,
    Typography,
} from '@mui/material';
import type {Theme} from '@mui/material/styles';
import EmailOutlined from '@mui/icons-material/EmailOutlined';
import LockOutlined from '@mui/icons-material/LockOutlined';
import PhonelinkLock from '@mui/icons-material/PhonelinkLock';
import Security from '@mui/icons-material/Security';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import {useNavigate} from 'react-router-dom';
import ReCAPTCHA from 'react-google-recaptcha';

import {ApiError, api, primeCsrfToken, type LoginRequest, type PublicUser} from '../../lib/api';
import {makeVerifier, deriveKEK} from '../../lib/crypto/argon2';
import {unwrapDEK} from '../../lib/crypto/unwrap';
import {useAuth} from '../../auth/auth-context';
import {useCrypto} from '../../lib/crypto/crypto-context';
import useCaptchaConfig from '../../lib/hooks/useCaptchaConfig';

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

export default function LoginCard({onSuccess, onSwitchToSignup}: Props) {
    const [identifier, setIdentifier] = useState('');
    const [mp, setMp] = useState('');
    const [show, setShow] = useState(false);
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
    const [pendingLogin, setPendingLogin] = useState<{ email: string; saltClient: string } | null>(null);
    const [mfaRequired, setMfaRequired] = useState(false);
    const [mfaCode, setMfaCode] = useState('');
    const [recoveryCode, setRecoveryCode] = useState('');
    const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);
    const [resendBusy, setResendBusy] = useState(false);
    const [captchaToken, setCaptchaToken] = useState<string | null>(null);
    const [captchaError, setCaptchaError] = useState<string | null>(null);

    const {login} = useAuth();
    const {setDEK, disarm, lockNow} = useCrypto();
    const navigate = useNavigate();
    const captchaRef = useRef<ReCAPTCHA | null>(null);

    const {config: captchaConfig, loading: captchaLoading, error: captchaConfigError} = useCaptchaConfig();
    const captchaEnabled = Boolean(
        captchaConfig?.enabled
        && captchaConfig.provider === 'RECAPTCHA'
        && captchaConfig.siteKey
    );
    const siteKey = captchaEnabled ? captchaConfig?.siteKey ?? '' : '';

    const trimmedIdentifier = useMemo(() => identifier.trim(), [identifier]);
    const disabled = busy
        || captchaLoading
        || Boolean(captchaConfigError)
        || !trimmedIdentifier
        || !mp
        || (mfaRequired && !mfaCode.trim() && !recoveryCode.trim())
        || (captchaEnabled && !captchaToken);

    useEffect(() => {
        setPendingLogin(null);
        setMfaRequired(false);
        setMfaCode('');
        setRecoveryCode('');
        setMsg(null);
        setUnverifiedEmail(null);
        if (captchaEnabled) {
            captchaRef.current?.reset();
            setCaptchaToken(null);
            setCaptchaError(null);
        }
    }, [trimmedIdentifier, captchaEnabled]);

    async function handleSubmit() {
        if (disabled) {
            if (captchaEnabled && !captchaToken) {
                setCaptchaError('Please complete the CAPTCHA challenge.');
            }
            return;
        }
        setMsg(null);
        setBusy(true);
        let attemptedEmail: string | null = null;
        try {
            lockNow();
            disarm();

            let loginEmail = pendingLogin?.email ?? null;
            let saltClient = pendingLogin?.saltClient ?? null;

            if (!loginEmail || !saltClient || !mfaRequired) {
                const {saltClient: fetchedSalt, email: canonicalEmail} = await api.getSalt(trimmedIdentifier);
                loginEmail = canonicalEmail;
                saltClient = fetchedSalt;
                setPendingLogin({email: canonicalEmail, saltClient: fetchedSalt});
            }

            if (!loginEmail || !saltClient) {
                throw new Error('Unable to determine login credentials');
            }

            const verifier = await makeVerifier(loginEmail, mp, saltClient);
            await primeCsrfToken();

            const payload: LoginRequest = {
                email: loginEmail,
                verifier,
                ...(captchaEnabled ? {captchaToken} : {}),
            };

            if (mfaRequired) {
                const trimmedMfa = mfaCode.trim();
                const trimmedRecovery = recoveryCode.trim();
                if (trimmedMfa) payload.mfaCode = trimmedMfa;
                if (trimmedRecovery) payload.recoveryCode = trimmedRecovery;
            }

            attemptedEmail = loginEmail;
            const data = await api.login(payload);

            login(data.user);

            const kek = await deriveKEK(mp, data.user.saltClient);
            const dek = await unwrapDEK(kek, data.user.dekEncrypted, data.user.dekNonce);
            setDEK(dek);

            await primeCsrfToken();
            setPendingLogin(null);
            setMfaRequired(false);
            setMfaCode('');
            setRecoveryCode('');
            setUnverifiedEmail(null);
            onSuccess?.(data.user, mp);
            await Promise.resolve();
            navigate('/dashboard', {replace: true});
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
                if (e.status === 401 && normalized === 'Invalid MFA challenge') {
                    const alreadyPrompted = mfaRequired;
                    setMfaRequired(true);
                    setUnverifiedEmail(null);
                    setMsg({
                        type: 'error',
                        text: alreadyPrompted
                            ? 'Invalid multi-factor authentication code. Try again or use a recovery code.'
                            : 'Multi-factor authentication required. Enter a code from your authenticator app or one of your recovery codes to continue.',
                    });
                } else if (e.status === 403 && errorCode === 'EMAIL_NOT_VERIFIED') {
                    const emailForResend = attemptedEmail ?? pendingLogin?.email ?? null;
                    if (emailForResend) {
                        setUnverifiedEmail(emailForResend);
                    }
                    setPendingLogin(null);
                    setMfaRequired(false);
                    setMfaCode('');
                    setRecoveryCode('');
                    setMsg({
                        type: 'error',
                        text: normalized
                            || 'You need to verify your email address before logging in. Use the link we sent you or request a new one below.',
                    });
                } else {
                    setPendingLogin(null);
                    setMfaRequired(false);
                    setMfaCode('');
                    setRecoveryCode('');
                    setUnverifiedEmail(null);
                    setMsg({
                        type: 'error',
                        text: normalized || 'Something went wrong',
                    });
                }
            } else {
                setPendingLogin(null);
                setMfaRequired(false);
                setMfaCode('');
                setRecoveryCode('');
                setUnverifiedEmail(null);
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

    async function handleResendVerification() {
        if (!unverifiedEmail || resendBusy) return;
        setResendBusy(true);
        try {
            const response = await api.resendVerification(unverifiedEmail);
            const message = response?.message?.trim()
                || 'If an account exists, a verification email has been sent.';
            setMsg({type: 'success', text: message});
        } catch (error) {
            if (error instanceof ApiError) {
                const message = typeof error.message === 'string' ? error.message : '';
                const details = typeof error.data === 'object' && error.data && 'message' in error.data
                    ? String((error.data as { message?: unknown }).message ?? '')
                    : '';
                const normalized = (message || details || '').trim();
                setMsg({
                    type: 'error',
                    text: normalized || 'Unable to resend verification email right now.',
                });
            } else {
                const message = error instanceof Error ? error.message : 'Unable to resend verification email right now.';
                setMsg({
                    type: 'error',
                    text: message || 'Unable to resend verification email right now.',
                });
            }
        } finally {
            setResendBusy(false);
        }
    }

    const submitOnEnter = (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' && !disabled) handleSubmit();
    };

    const handleSwitchToSignupClick = () => {
        setPendingLogin(null);
        setMfaRequired(false);
        setMfaCode('');
        setRecoveryCode('');
        setMsg(null);
        if (captchaEnabled) {
            captchaRef.current?.reset();
            setCaptchaToken(null);
            setCaptchaError(null);
        }
        onSwitchToSignup?.();
    };

    return (
        <Box
            sx={(theme) => ({
                width: '100%',
                maxWidth: {xs: 460, sm: 520},
                mx: 'auto',
                p: {xs: 3, sm: 4},
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
                    <Typography variant="overline" sx={{letterSpacing: 1.6, fontWeight: 700, opacity: 0.85}}>
                        Welcome back
                    </Typography>
                    <Typography variant="h4" sx={{fontWeight: 800, lineHeight: 1.1}}>
                        Access your vault
                    </Typography>
                    <Typography variant="body2" sx={{opacity: 0.9}}>
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
                                    <EmailOutlined fontSize="small"/>
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
                    {captchaLoading ? (
                        <Stack spacing={1} alignItems="center">
                            <CircularProgress size={32} color="inherit"/>
                            <Typography variant="body2" sx={{opacity: 0.85}}>
                                Preparing CAPTCHA challenge…
                            </Typography>
                        </Stack>
                    ) : null}
                    {captchaConfigError ? (
                        <Alert severity="error">
                            Unable to load the CAPTCHA challenge. Please refresh the page and try again.
                        </Alert>
                    ) : null}
                    {captchaEnabled ? (
                        <Stack spacing={1} alignItems="center">
                            <ReCAPTCHA
                                ref={captchaRef}
                                sitekey={siteKey}
                                onChange={(token) => {
                                    setCaptchaToken(token);
                                    if (token) setCaptchaError(null);
                                }}
                                onExpired={() => {
                                    setCaptchaToken(null);
                                    setCaptchaError('Please complete the CAPTCHA challenge.');
                                }}
                                onErrored={() => {
                                    setCaptchaToken(null);
                                    setCaptchaError('Unable to load the CAPTCHA challenge. Please try again.');
                                }}
                            />
                            {captchaError ? (
                                <FormHelperText error>{captchaError}</FormHelperText>
                            ) : null}
                        </Stack>
                    ) : null}
                    {mfaRequired ? (
                        <Stack spacing={1.5}>
                            <Typography variant="body2" sx={{opacity: 0.9}}>
                                Enter a verification code from your authenticator app or a recovery code to finish
                                signing in.
                            </Typography>
                            <FormControl fullWidth variant="outlined" sx={(theme) => fieldStyles(theme)}>
                                <InputLabel htmlFor="login-mfa-code">Authenticator code</InputLabel>
                                <OutlinedInput
                                    id="login-mfa-code"
                                    type="text"
                                    value={mfaCode}
                                    onChange={(e) => {
                                        const value = e.target.value;
                                        setMfaCode(value);
                                        if (value.trim()) {
                                            setRecoveryCode('');
                                        }
                                    }}
                                    onKeyDown={submitOnEnter}
                                    startAdornment={
                                        <InputAdornment position="start">
                                            <PhonelinkLock fontSize="small"/>
                                        </InputAdornment>
                                    }
                                    label="Authenticator code"
                                />
                            </FormControl>
                            <Typography variant="caption" sx={{textAlign: 'center', opacity: 0.8}}>
                                or
                            </Typography>
                            <FormControl fullWidth variant="outlined" sx={(theme) => fieldStyles(theme)}>
                                <InputLabel htmlFor="login-recovery-code">Recovery code</InputLabel>
                                <OutlinedInput
                                    id="login-recovery-code"
                                    type="text"
                                    value={recoveryCode}
                                    onChange={(e) => {
                                        const value = e.target.value;
                                        setRecoveryCode(value);
                                        if (value.trim()) {
                                            setMfaCode('');
                                        }
                                    }}
                                    onKeyDown={submitOnEnter}
                                    startAdornment={
                                        <InputAdornment position="start">
                                            <Security fontSize="small"/>
                                        </InputAdornment>
                                    }
                                    label="Recovery code"
                                />
                            </FormControl>
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
                            boxShadow: '0 14px 32px rgba(99,102,241,0.35)',
                            '&:hover': {background: gradientBtn, opacity: 0.95},
                            '&.Mui-disabled': {background: gradientBtn, opacity: 0.55},
                        }}
                        variant="contained"
                    >
                        {busy ? <CircularProgress size={22} sx={{color: '#fff'}}/> : 'Log in'}
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

                    {unverifiedEmail && (
                        <Stack
                            spacing={1.5}
                            sx={{
                                p: 2,
                                borderRadius: 2,
                                backgroundColor: 'rgba(15,23,42,0.35)',
                                border: '1px solid rgba(148,163,184,0.35)',
                            }}
                        >
                            <Typography variant="body2" sx={{opacity: 0.9, lineHeight: 1.6}}>
                                Your account email <strong>{unverifiedEmail}</strong> hasn&apos;t been verified yet.
                                Click below to get a new verification link.
                            </Typography>
                            <Button
                                onClick={handleResendVerification}
                                disabled={resendBusy}
                                variant="outlined"
                                sx={{
                                    alignSelf: 'center',
                                    px: 3,
                                    borderRadius: 999,
                                    textTransform: 'none',
                                    fontWeight: 700,
                                    borderColor: 'rgba(191,219,254,0.8)',
                                    color: '#e0f2fe',
                                    '&:hover': {
                                        borderColor: 'rgba(191,219,254,1)',
                                        backgroundColor: 'rgba(14,165,233,0.15)',
                                    },
                                    '&.Mui-disabled': {opacity: 0.6},
                                }}
                            >
                                {resendBusy ?
                                    <CircularProgress size={20} sx={{color: '#e0f2fe'}}/> : 'Resend verification email'}
                            </Button>
                        </Stack>
                    )}

                    <Stack direction="row" spacing={1} justifyContent="center" alignItems="center">
                        <Typography
                            variant="body2"
                            sx={{opacity: 0.85, display: 'flex', alignItems: 'center'}}
                        >
                            Need an account?
                        </Typography>
                        <Button
                            onClick={handleSwitchToSignupClick}
                            color="inherit"
                            size="small"
                            sx={{textTransform: 'none', fontWeight: 700, px: 0, minWidth: 0}}
                        >
                            Sign up
                        </Button>
                    </Stack>
                </Stack>
            </Stack>
        </Box>
    );
}