import {useEffect, useMemo, useState} from 'react';
import {
    Alert,
    Box,
    Button,
    Card,
    CardContent,
    CircularProgress,
    Divider,
    FormControl,
    FormHelperText,
    IconButton,
    InputAdornment,
    InputLabel,
    OutlinedInput,
    Stack,
    Typography,
} from '@mui/material';
import {useTheme} from '@mui/material/styles';
import EmailOutlined from '@mui/icons-material/EmailOutlined';
import LockOutlined from '@mui/icons-material/LockOutlined';
import PhonelinkLock from '@mui/icons-material/PhonelinkLock';
import Security from '@mui/icons-material/Security';
import VpnKey from '@mui/icons-material/VpnKey';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import {useNavigate} from 'react-router-dom';

import {ApiError, api, primeCsrfToken, type LoginRequest, type PublicUser} from '../../lib/api';
import {makeVerifier, deriveKEK} from '../../lib/crypto/argon2';
import {unwrapDEK} from '../../lib/crypto/unwrap';
import {useAuth} from '../../auth/auth-context';
import {useCrypto} from '../../lib/crypto/crypto-context';
import CaptchaChallenge from './CaptchaChallenge';
import {useCaptchaChallengeState} from './useCaptchaChallengeState';
import {extractApiErrorDetails} from '../../lib/api-error';
import {assertionToJSON, decodeRequestOptions, isWebAuthnSupported} from '../../lib/webauthn';
import {rememberDek, restoreDek} from '../../lib/crypto/dek-storage';

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
    const [passkeyBusy, setPasskeyBusy] = useState(false);

    const {login} = useAuth();
    const {setDEK, disarm, lockNow} = useCrypto();
    const navigate = useNavigate();
    const theme = useTheme();
    const captchaTheme = theme.palette.mode === 'dark' ? 'dark' : 'light';
    const [passkeySupported] = useState(() => isWebAuthnSupported());
    const trimmedIdentifier = useMemo(() => identifier.trim(), [identifier]);
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
    } = useCaptchaChallengeState({boundValue: trimmedIdentifier || null});
    const disabled = busy
        || captchaLoading
        || Boolean(captchaConfigError)
        || !trimmedIdentifier
        || !mp
        || (mfaRequired && !mfaCode.trim() && !recoveryCode.trim())
        || (captchaEnabled && !captchaToken);
    const passkeyDisabled = busy
        || captchaLoading
        || Boolean(captchaConfigError)
        || !trimmedIdentifier
        || (captchaEnabled && !captchaToken);

    useEffect(() => {
        setPendingLogin(null);
        setMfaRequired(false);
        setMfaCode('');
        setRecoveryCode('');
        setMsg(null);
        setUnverifiedEmail(null);
    }, [trimmedIdentifier]);

    async function handlePasskeyLogin() {
        if (!passkeySupported) {
            setMsg({type: 'error', text: 'Passkeys are not supported in this browser.'});
            return;
        }
        if (!trimmedIdentifier) {
            setMsg({type: 'error', text: 'Enter your email address to use a passkey.'});
            return;
        }
        if (captchaEnabled && !captchaToken) {
            setCaptchaError('Please complete the CAPTCHA challenge.');
            setMsg({type: 'error', text: 'Complete the CAPTCHA challenge to continue.'});
            return;
        }

        setMsg(null);
        setBusy(true);
        setPasskeyBusy(true);
        let attemptedEmail: string | null = null;
        try {
            lockNow();
            disarm();

            const {saltClient, email: canonicalEmail} = await api.getSalt(trimmedIdentifier);
            attemptedEmail = canonicalEmail;
            setPendingLogin({email: canonicalEmail, saltClient});

            await primeCsrfToken();
            const optionsResponse = await api.startPasskeyLogin({
                email: canonicalEmail,
                ...(captchaEnabled ? {captchaToken} : {}),
            });
            const publicKey = decodeRequestOptions(optionsResponse.publicKey);
            const credential = await navigator.credentials.get({publicKey});
            if (!credential) {
                setMsg({type: 'error', text: 'Passkey authentication was cancelled.'});
                return;
            }
            if (!(credential instanceof PublicKeyCredential)) {
                throw new Error('Unexpected credential type returned by the browser.');
            }
            const assertion = assertionToJSON(credential);

            await primeCsrfToken();
            const data = await api.finishPasskeyLogin({
                requestId: optionsResponse.requestId,
                credential: assertion,
            });

            login(data.user);

            let unlocked = false;

            if (mp) {
                try {
                    const kek = await deriveKEK(mp, data.user.saltClient);
                    const dek = await unwrapDEK(kek, data.user.dekEncrypted, data.user.dekNonce);
                    await rememberDek(data.user.id, dek);
                    setDEK(dek);
                    unlocked = true;
                } catch (error) {
                    console.warn('Failed to unlock vault with provided master password.', error);
                    setDEK(null);
                }
            }

            if (!unlocked) {
                const remembered = await restoreDek(data.user.id);
                if (remembered) {
                    setDEK(remembered);
                    unlocked = true;
                } else if (!mp) {
                    setDEK(null);
                }
            }

            await primeCsrfToken();
            setPendingLogin(null);
            setMfaRequired(false);
            setMfaCode('');
            setRecoveryCode('');
            setUnverifiedEmail(null);
            onSuccess?.(data.user, mp);
            await Promise.resolve();
            navigate('/dashboard', {replace: true});
        } catch (error) {
            if (error instanceof ApiError) {
                const {message: normalizedMessage, errorCode} = extractApiErrorDetails(error);
                if (error.status === 400 && errorCode === 'INVALID_CAPTCHA') {
                    console.warn('[CAPTCHA] Passkey login rejected due to invalid token.');
                    setCaptchaError('CAPTCHA verification failed. Please try again.');
                    setMsg({type: 'error', text: 'CAPTCHA verification failed. Please try again.'});
                } else if (error.status === 400 && errorCode === 'NO_PASSKEY') {
                    setMsg({
                        type: 'error',
                        text: normalizedMessage || 'No passkeys are registered for this account.',
                    });
                } else if (error.status === 403 && errorCode === 'EMAIL_NOT_VERIFIED') {
                    if (attemptedEmail) {
                        setUnverifiedEmail(attemptedEmail);
                    }
                    setMsg({
                        type: 'error',
                        text: normalizedMessage
                            || 'You need to verify your email address before logging in.',
                    });
                } else {
                    setMsg({
                        type: 'error',
                        text: normalizedMessage || 'Unable to sign in with your passkey right now.',
                    });
                }
            } else if (error instanceof DOMException) {
                if (error.name === 'NotAllowedError') {
                    setMsg({
                        type: 'error',
                        text: 'Passkey authentication timed out or was dismissed.',
                    });
                } else {
                    setMsg({
                        type: 'error',
                        text: error.message || 'Passkey authentication failed.',
                    });
                }
            } else {
                const message = error instanceof Error ? error.message : 'Unable to sign in with your passkey right now.';
                setMsg({type: 'error', text: message || 'Unable to sign in with your passkey right now.'});
            }
            setPendingLogin(null);
            setMfaRequired(false);
            setMfaCode('');
            setRecoveryCode('');
            setUnverifiedEmail(null);
        } finally {
            if (captchaEnabled) {
                resetCaptcha();
            }
            setBusy(false);
            setPasskeyBusy(false);
        }
    }

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
            await rememberDek(data.user.id, dek);
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
                const {message: normalizedMessage, errorCode} = extractApiErrorDetails(e);
                if (e.status === 400 && errorCode === 'INVALID_CAPTCHA') {
                    console.warn('[CAPTCHA] Login rejected due to invalid token.');
                    setCaptchaError('CAPTCHA verification failed. Please try again.');
                    setMsg({type: 'error', text: 'CAPTCHA verification failed. Please try again.'});
                    setPendingLogin(null);
                    setMfaRequired(false);
                    setMfaCode('');
                    setRecoveryCode('');
                    setUnverifiedEmail(null);
                } else if (e.status === 401 && normalizedMessage === 'Invalid MFA challenge') {
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
                        text: normalizedMessage
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
                        text: normalizedMessage || 'Something went wrong',
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
                resetCaptcha();
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
                const {message} = extractApiErrorDetails(error);
                setMsg({
                    type: 'error',
                    text: message || 'Unable to resend verification email right now.',
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
            resetCaptcha();
        }
        onSwitchToSignup?.();
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
                            Welcome back
                        </Typography>
                        <Typography variant="caption" color="text.secondary">
                            Sign in to access your vault
                        </Typography>
                    </Box>

                    <Stack spacing={1.5}>
                        <FormControl fullWidth variant="outlined" size="small">
                            <InputLabel htmlFor="login-identifier">Email or Username</InputLabel>
                            <OutlinedInput
                                id="login-identifier"
                                type="text"
                                value={identifier}
                                onChange={(e) => setIdentifier(e.target.value)}
                                onKeyDown={submitOnEnter}
                                startAdornment={
                                    <InputAdornment position="start">
                                        <EmailOutlined fontSize="small" color="action"/>
                                    </InputAdornment>
                                }
                                label="Email or Username"
                            />
                        </FormControl>

                        <FormControl fullWidth variant="outlined" size="small">
                            <InputLabel htmlFor="login-password">Master Password</InputLabel>
                            <OutlinedInput
                                id="login-password"
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
                        {mfaRequired ? (
                            <Stack spacing={1.5} sx={{ mt: 1, p: 2, bgcolor: 'action.hover', borderRadius: 2 }}>
                                <Typography variant="caption" fontWeight={600}>
                                    Two-factor authentication required
                                </Typography>
                                <FormControl fullWidth variant="outlined" size="small">
                                    <InputLabel htmlFor="login-mfa-code">Authenticator code</InputLabel>
                                    <OutlinedInput
                                        id="login-mfa-code"
                                        type="text"
                                        value={mfaCode}
                                        onChange={(e) => {
                                            const value = e.target.value;
                                            setMfaCode(value);
                                            if (value.trim()) setRecoveryCode('');
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
                                <Divider><Typography variant="caption">OR</Typography></Divider>
                                <FormControl fullWidth variant="outlined" size="small">
                                    <InputLabel htmlFor="login-recovery-code">Recovery code</InputLabel>
                                    <OutlinedInput
                                        id="login-recovery-code"
                                        type="text"
                                        value={recoveryCode}
                                        onChange={(e) => {
                                            const value = e.target.value;
                                            setRecoveryCode(value);
                                            if (value.trim()) setMfaCode('');
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

                    <Stack spacing={1.5}>
                        {passkeySupported ? (
                            <Button
                                onClick={() => { void handlePasskeyLogin(); }}
                                disabled={passkeyDisabled}
                                variant="outlined"
                                color="secondary"
                                size="medium"
                                startIcon={passkeyBusy ? <CircularProgress size={16} color="inherit"/> : <VpnKey/>}
                            >
                                {passkeyBusy ? 'Waiting...' : 'Sign in with passkey'}
                            </Button>
                        ) : null}

                        <Button
                            onClick={handleSubmit}
                            disabled={disabled}
                            variant="contained"
                            size="medium"
                            disableElevation
                        >
                            {busy ? <CircularProgress size={20} color="inherit"/> : 'Log in'}
                        </Button>

                        {msg && (
                            <Alert severity={msg.type} sx={{ py: 0, alignItems: 'center' }}>
                                {msg.text}
                            </Alert>
                        )}

                        {unverifiedEmail && (
                            <Stack
                                spacing={1}
                                sx={{ p: 1.5, bgcolor: 'warning.light', borderRadius: 1 }}
                            >
                                <Typography variant="caption" color="warning.contrastText">
                                    Email <strong>{unverifiedEmail}</strong> not verified.
                                </Typography>
                                <Button
                                    onClick={handleResendVerification}
                                    disabled={resendBusy}
                                    variant="outlined"
                                    color="inherit"
                                    size="small"
                                    sx={{ py: 0 }}
                                >
                                    {resendBusy ? 'Sending…' : 'Resend verification'}
                                </Button>
                            </Stack>
                        )}

                        <Box display="flex" justifyContent="center" alignItems="center" gap={1}>
                            <Typography variant="caption" color="text.secondary">
                                New here?
                            </Typography>
                            <Button
                                onClick={handleSwitchToSignupClick}
                                color="primary"
                                size="small"
                                sx={{ fontWeight: 600, minWidth: 'auto', p: 0.5 }}
                            >
                                Create an account
                            </Button>
                        </Box>
                    </Stack>
                </Stack>
            </CardContent>
        </Card>
    );
}
