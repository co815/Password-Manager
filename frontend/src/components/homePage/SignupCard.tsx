import {useCallback, useEffect, useMemo, useState} from 'react';
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
import {useTheme} from '@mui/material/styles';
import EmailOutlined from '@mui/icons-material/EmailOutlined';
import PersonOutline from '@mui/icons-material/PersonOutline';
import LockOutlined from '@mui/icons-material/LockOutlined';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';

import {ApiError, api, primeCsrfToken} from '../../lib/api';
import {createAccountMaterial} from '../../lib/crypto/keys';
import {makeVerifier} from '../../lib/crypto/argon2';
import CaptchaChallenge from './CaptchaChallenge';
import {authButtonStyles, createFieldStyles} from './authStyles';
import {useCaptchaChallengeState} from './useCaptchaChallengeState';
import {extractApiErrorDetails} from '../../lib/api-error';
import {
    MIN_ACCEPTABLE_PASSWORD_SCORE,
    assessPasswordStrength,
    getPasswordStrengthColor,
    getPasswordStrengthLabel,
} from '../../lib/passwordStrength';

type Props = {
    onSwitchToLogin?: () => void;
};

export default function SignupCard({onSwitchToLogin}: Props) {
    const [email, setEmail] = useState('');
    const [username, setUsername] = useState('');
    const [mp, setMp] = useState('');
    const [mp2, setMp2] = useState('');
    const [show, setShow] = useState(false);
    const [busy, setBusy] = useState(false);
    const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
    const theme = useTheme();
    const captchaTheme = theme.palette.mode === 'dark' ? 'dark' : 'light';

    const {
        captchaEnabled,
        captchaProvider,
        siteKey,
        captchaLoading,
        captchaConfigError,
        reloadCaptchaConfig,
        captchaRef,
        captchaToken,
        setCaptchaToken,
        captchaError,
        setCaptchaError,
        resetCaptcha,
    } = useCaptchaChallengeState();

    const trimmedEmail = useMemo(() => email.trim().toLowerCase(), [email]);
    const trimmedUsername = useMemo(() => username.trim(), [username]);
    const pwdStrength = useMemo(
        () => assessPasswordStrength(mp, [trimmedEmail, trimmedUsername]),
        [mp, trimmedEmail, trimmedUsername]
    );
    const pwdScore = pwdStrength.score;
    const pwdProgress = (pwdScore / 4) * 100;
    const strengthLabel = mp ? getPasswordStrengthLabel(pwdScore) : 'No password entered';
    const strengthSuggestions = mp
        ? pwdStrength.suggestions
        : [
              'Use a long, unique passphrase to protect your vault.',
              'Avoid personal information or common phrases that can be guessed.',
          ];
    const strengthColor = getPasswordStrengthColor(pwdScore);
    const passwordTooWeak =
        Boolean(mp) && (pwdStrength.compromised || pwdStrength.score < MIN_ACCEPTABLE_PASSWORD_SCORE);
    const passwordWarning = !mp
        ? null
        : pwdStrength.compromised
            ? 'This password was found in known breaches. Please choose a different one.'
            : pwdStrength.score < MIN_ACCEPTABLE_PASSWORD_SCORE
                ? 'Your master password is too weak. Make it longer and mix words, numbers, and symbols.'
                : null;
    const usernameError = !!trimmedUsername && trimmedUsername.length < 4;
    const confirmError = !!mp2 && mp2 !== mp;
    const disabled =
        busy
        || captchaLoading
        || Boolean(captchaConfigError)
        || !trimmedEmail
        || !trimmedUsername
        || trimmedUsername.length < 4
        || !mp
        || mp !== mp2
        || passwordTooWeak
        || (captchaEnabled && !captchaToken);

    const handleSwitchToLogin = useCallback(() => {
        setMsg(null);
        if (captchaEnabled) {
            resetCaptcha();
        }
        onSwitchToLogin?.();
    }, [captchaEnabled, onSwitchToLogin, resetCaptcha]);

    useEffect(() => {
        if (msg?.type === 'success') {
            const timer = setTimeout(() => {
                handleSwitchToLogin();
            }, 1800);
            return () => clearTimeout(timer);
        }
        return undefined;
    }, [handleSwitchToLogin, msg]);

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
                resetCaptcha();
            }
        } catch (e: unknown) {
            if (e instanceof ApiError) {
                const {message: normalizedMessage, errorCode} = extractApiErrorDetails(e);
                if (e.status === 400 && errorCode === 'INVALID_CAPTCHA') {
                    console.warn('[CAPTCHA] Signup rejected due to invalid token.');
                    setCaptchaError('CAPTCHA verification failed. Please try again.');
                    setMsg({type: 'error', text: 'CAPTCHA verification failed. Please try again.'});
                } else {
                    setMsg({type: 'error', text: normalizedMessage || 'Something went wrong'});
                }
            } else {
                const message = e instanceof Error ? e.message : 'Something went wrong';
                setMsg({type: 'error', text: message || 'Something went wrong'});
            }
        } finally {
            if (captchaEnabled) {
                resetCaptcha();
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
                    <FormControl fullWidth variant="outlined" sx={(theme) => createFieldStyles(theme)}>
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

                    <FormControl fullWidth variant="outlined" error={usernameError} sx={(theme) => createFieldStyles(theme)}>
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

                    <FormControl fullWidth variant="outlined" sx={(theme) => createFieldStyles(theme)}>
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
                        value={pwdProgress}
                        sx={{
                            height: 6,
                            borderRadius: 3,
                            mx: 0.5,
                            '& .MuiLinearProgress-bar': {
                                background: strengthColor,
                            },
                            backgroundColor: 'rgba(148,163,184,0.35)',
                        }}
                    />
                    <Box sx={{px: 0.5, mt: 0.5}}>
                        <Typography
                            variant="caption"
                            sx={{fontWeight: 600, display: 'block'}}
                            color={pwdStrength.compromised ? 'error.main' : 'inherit'}
                        >
                            {strengthLabel}
                        </Typography>
                        {mp ? (
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

                    <FormControl fullWidth variant="outlined" error={confirmError} sx={(theme) => createFieldStyles(theme)}>
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
                        sx={authButtonStyles}
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