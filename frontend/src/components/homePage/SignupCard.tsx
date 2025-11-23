import {useCallback, useEffect, useMemo, useState} from 'react';
import type {KeyboardEvent} from 'react';
import {
    Alert,
    Box,
    Button,
    Card,
    CardContent,
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
        <Card
            elevation={1}
            sx={{
                width: '100%',
                maxWidth: 480,
                borderRadius: 2,
            }}
        >
            <CardContent sx={{ p: { xs: 3, sm: 4 } }}>
                <Stack spacing={3}>
                    <Box textAlign="center">
                        <Typography variant="h5" sx={{ fontWeight: 700, mb: 1 }}>
                            Create your vault
                        </Typography>
                        <Typography variant="body2" color="text.secondary">
                            Join Password Manager securely
                        </Typography>
                    </Box>

                    <Stack spacing={2}>
                        <FormControl fullWidth variant="outlined">
                            <InputLabel htmlFor="signup-email">Email</InputLabel>
                            <OutlinedInput
                                id="signup-email"
                                type="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                onKeyDown={submitOnEnter}
                                startAdornment={
                                    <InputAdornment position="start">
                                        <EmailOutlined fontSize="small" color="action"/>
                                    </InputAdornment>
                                }
                                label="Email"
                            />
                        </FormControl>

                        <FormControl fullWidth variant="outlined" error={usernameError}>
                            <InputLabel htmlFor="signup-username">Username</InputLabel>
                            <OutlinedInput
                                id="signup-username"
                                type="text"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                onKeyDown={submitOnEnter}
                                startAdornment={
                                    <InputAdornment position="start">
                                        <PersonOutline fontSize="small" color="action"/>
                                    </InputAdornment>
                                }
                                label="Username"
                            />
                            <FormHelperText>
                                {usernameError ? 'Username must be at least 4 characters long' : ' '}
                            </FormHelperText>
                        </FormControl>

                        <FormControl fullWidth variant="outlined">
                            <InputLabel htmlFor="signup-password">Master Password</InputLabel>
                            <OutlinedInput
                                id="signup-password"
                                type={show ? 'text' : 'password'}
                                value={mp}
                                onChange={(e) => setMp(e.target.value)}
                                onKeyDown={submitOnEnter}
                                startAdornment={
                                    <InputAdornment position="start">
                                        <LockOutlined fontSize="small" color="action"/>
                                    </InputAdornment>
                                }
                                endAdornment={
                                    <InputAdornment position="end">
                                        <IconButton
                                            onClick={() => setShow((s) => !s)}
                                            edge="end"
                                            aria-label="toggle password visibility"
                                        >
                                            {show ? <VisibilityOff/> : <Visibility/>}
                                        </IconButton>
                                    </InputAdornment>
                                }
                                label="Master Password"
                            />
                        </FormControl>

                        <Box>
                            <LinearProgress
                                variant="determinate"
                                value={pwdProgress}
                                sx={{
                                    height: 4,
                                    borderRadius: 2,
                                    mb: 1,
                                    '& .MuiLinearProgress-bar': {
                                        backgroundColor: strengthColor,
                                    },
                                    backgroundColor: 'action.hover',
                                }}
                            />
                            <Typography
                                variant="caption"
                                display="block"
                                fontWeight={600}
                                color={pwdStrength.compromised ? 'error' : 'text.primary'}
                            >
                                {strengthLabel}
                            </Typography>
                            {mp && (
                                <Typography variant="caption" display="block" color="text.secondary">
                                    Estimated crack time: {pwdStrength.crackTime}
                                </Typography>
                            )}
                            <Box component="ul" sx={{ pl: 2, mt: 0.5, mb: 0 }}>
                                {strengthSuggestions.map((suggestion, index) => (
                                    <Typography key={index} component="li" variant="caption" color="text.secondary">
                                        {suggestion}
                                    </Typography>
                                ))}
                            </Box>
                            {passwordWarning && (
                                <Typography variant="caption" color="error" fontWeight={600} sx={{ mt: 1, display: 'block' }}>
                                    {passwordWarning}
                                </Typography>
                            )}
                        </Box>

                        <FormControl fullWidth variant="outlined" error={confirmError}>
                            <InputLabel htmlFor="signup-confirm">Confirm Password</InputLabel>
                            <OutlinedInput
                                id="signup-confirm"
                                type={show ? 'text' : 'password'}
                                value={mp2}
                                onChange={(e) => setMp2(e.target.value)}
                                onKeyDown={submitOnEnter}
                                label="Confirm Password"
                            />
                            <FormHelperText>{confirmError ? 'Passwords do not match' : ' '}</FormHelperText>
                        </FormControl>

                        {captchaLoading ? (
                            <Stack spacing={1} alignItems="center">
                                <CircularProgress size={32}/>
                                <Typography variant="body2" color="text.secondary">
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
                                Unable to load the CAPTCHA challenge.
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
                                        setCaptchaError('The CAPTCHA challenge expired.');
                                    }}
                                    onErrored={(message) => {
                                        setCaptchaToken(null);
                                        setCaptchaError(message ?? 'Unable to load CAPTCHA.');
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
                            variant="contained"
                            size="large"
                            disableElevation
                        >
                            {busy ? <CircularProgress size={24} color="inherit"/> : 'Create account'}
                        </Button>

                        {msg && (
                            <Alert severity={msg.type}>
                                {msg.text}
                            </Alert>
                        )}

                        <Box display="flex" justifyContent="center" alignItems="center" gap={1}>
                            <Typography variant="body2" color="text.secondary">
                                Already have an account?
                            </Typography>
                            <Button
                                onClick={handleSwitchToLogin}
                                color="primary"
                                sx={{ fontWeight: 600 }}
                            >
                                Log in
                            </Button>
                        </Box>
                    </Stack>
                </Stack>
            </CardContent>
        </Card>
    );
}
