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
    Grid,
    IconButton,
    InputAdornment,
    InputLabel,
    LinearProgress,
    OutlinedInput,
    Stack,
    Tooltip,
    Typography,
} from '@mui/material';
import {useTheme} from '@mui/material/styles';
import EmailOutlined from '@mui/icons-material/EmailOutlined';
import PersonOutline from '@mui/icons-material/PersonOutline';
import LockOutlined from '@mui/icons-material/LockOutlined';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import InfoOutlined from '@mui/icons-material/InfoOutlined';

import {ApiError, api, primeCsrfToken} from '../../lib/api';
import {createAccountMaterial} from '../../lib/crypto/keys';
import { generateLoginHash, fromB64 } from '../../lib/crypto';
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

    const strengthSuggestionsText = mp
        ? pwdStrength.suggestions.join(' ')
        : 'Use a long, unique passphrase. Avoid common phrases.';

    const strengthColor = getPasswordStrengthColor(pwdScore);
    const passwordTooWeak =
        Boolean(mp) && (pwdStrength.compromised || pwdStrength.score < MIN_ACCEPTABLE_PASSWORD_SCORE);

    const passwordWarning = !mp
        ? null
        : pwdStrength.compromised
            ? 'Breached password.'
            : pwdStrength.score < MIN_ACCEPTABLE_PASSWORD_SCORE
                ? 'Too weak.'
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
            const loginHash = await generateLoginHash(mp, fromB64(saltClient));
            await primeCsrfToken();
            await api.register({
                email: trimmedEmail,
                username: trimmedUsername,
                verifier: loginHash,
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
                maxWidth: { xs: '100%', sm: 480 },
                borderRadius: 2,
            }}
        >
            <CardContent sx={{ p: { xs: 2, sm: 3 } }}>
                <Stack spacing={2}>
                    <Box textAlign="center">
                        <Typography variant="h6" sx={{ fontWeight: 700 }}>
                            Create your vault
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                            Join Password Manager securely
                        </Typography>
                    </Box>

                    <Stack spacing={1.5}>
                        <Grid container spacing={1.5}>
                            <Grid size={{ xs: 12, sm: 6 }}>
                                <FormControl fullWidth variant="outlined" size="small">
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
                            </Grid>
                            <Grid size={{ xs: 12, sm: 6 }}>
                                <FormControl fullWidth variant="outlined" size="small" error={usernameError}>
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
                                    {usernameError && (
                                        <FormHelperText sx={{ m: 0, mt: 0.5 }}>
                                            Min 4 chars
                                        </FormHelperText>
                                    )}
                                </FormControl>
                            </Grid>
                        </Grid>

                        <FormControl fullWidth variant="outlined" size="small">
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
                                            size="small"
                                            aria-label="toggle password visibility"
                                        >
                                            {show ? <VisibilityOff fontSize="small"/> : <Visibility fontSize="small"/>}
                                        </IconButton>
                                    </InputAdornment>
                                }
                                label="Master Password"
                            />
                        </FormControl>

                        <Box>
                            <Box display="flex" alignItems="center" gap={1} mb={0.5}>
                                <LinearProgress
                                    variant="determinate"
                                    value={pwdProgress}
                                    sx={{
                                        flexGrow: 1,
                                        height: 4,
                                        borderRadius: 2,
                                        '& .MuiLinearProgress-bar': {
                                            backgroundColor: strengthColor,
                                        },
                                        backgroundColor: 'action.hover',
                                    }}
                                />
                                <Tooltip title={strengthSuggestionsText} arrow placement="top">
                                    <InfoOutlined fontSize="small" color="action" sx={{ fontSize: 16, cursor: 'help' }} />
                                </Tooltip>
                            </Box>

                            <Box display="flex" justifyContent="space-between" alignItems="center">
                                <Typography
                                    variant="caption"
                                    fontWeight={600}
                                    color={pwdStrength.compromised ? 'error' : 'text.primary'}
                                >
                                    {strengthLabel}
                                </Typography>
                                {passwordWarning && (
                                    <Typography variant="caption" color="error" fontWeight={600}>
                                        {passwordWarning}
                                    </Typography>
                                )}
                            </Box>
                        </Box>

                        <FormControl fullWidth variant="outlined" size="small" error={confirmError}>
                            <InputLabel htmlFor="signup-confirm">Confirm Password</InputLabel>
                            <OutlinedInput
                                id="signup-confirm"
                                type={show ? 'text' : 'password'}
                                value={mp2}
                                onChange={(e) => setMp2(e.target.value)}
                                onKeyDown={submitOnEnter}
                                label="Confirm Password"
                            />
                            {confirmError && (
                                <FormHelperText sx={{ m: 0, mt: 0.5 }}>Passwords do not match</FormHelperText>
                            )}
                        </FormControl>

                        {captchaLoading ? (
                            <Stack spacing={1} alignItems="center">
                                <CircularProgress size={24}/>
                                <Typography variant="caption" color="text.secondary">
                                    Preparing CAPTCHA...
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
                                Captcha Error
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
                                        setCaptchaError('Expired');
                                    }}
                                    onErrored={(message) => {
                                        setCaptchaToken(null);
                                        setCaptchaError(message ?? 'Error');
                                    }}
                                />
                                {captchaError ? (
                                    <FormHelperText error>{captchaError}</FormHelperText>
                                ) : null}
                            </Stack>
                        ) : null}
                    </Stack>

                    <Stack spacing={1.5}>
                        <Button
                            onClick={handleSubmit}
                            disabled={disabled}
                            variant="contained"
                            size="medium"
                            disableElevation
                        >
                            {busy ? <CircularProgress size={20} color="inherit"/> : 'Create account'}
                        </Button>

                        {msg && (
                            <Alert severity={msg.type} sx={{ py: 0, alignItems: 'center' }}>
                                {msg.text}
                            </Alert>
                        )}

                        <Box display="flex" justifyContent="center" alignItems="center" gap={1}>
                            <Typography variant="caption" color="text.secondary">
                                Already have an account?
                            </Typography>
                            <Button
                                onClick={handleSwitchToLogin}
                                color="primary"
                                size="small"
                                sx={{ fontWeight: 600, minWidth: 'auto', p: 0.5 }}
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
