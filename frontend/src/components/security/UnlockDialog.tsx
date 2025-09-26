import { useState } from 'react';
import {
    Dialog, DialogTitle, DialogContent, DialogActions,
    Button, TextField, InputAdornment, IconButton, Typography
} from '@mui/material';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import { deriveKEK } from '../../lib/crypto/argon2';
import { unwrapDEK } from '../../lib/crypto/unwrap';
import { useCrypto } from '../../lib/crypto/crypto-context';
import { useAuth } from '../../auth/auth-context';

export default function UnlockDialog({ open }: { open: boolean }) {
    const { setDEK } = useCrypto();
    const { user: authUser } = useAuth();
    const [mp, setMp] = useState('');
    const [show, setShow] = useState(false);
    const [busy, setBusy] = useState(false);
    const [err, setErr] = useState<string | null>(null);

    const onUnlock = async () => {
        if (!mp || busy) return;
        setBusy(true);
        setErr(null);

        const profile = authUser;
        if (!profile?.id) {
            setErr('Master password invalid');
            setBusy(false);
            return;
        }

        try {
            const kek = await deriveKEK(mp, profile.saltClient);
            const dek = await unwrapDEK(kek, profile.dekEncrypted, profile.dekNonce);
            setDEK(dek);
            setMp('');
        } catch {
            setErr('Master password invalid');
        } finally {
            setBusy(false);
        }
    };

    return (
        <Dialog
            open={open}
            fullWidth
            maxWidth="xs"
            onClose={() => {}} // forțăm rămânerea deschis
            slotProps={{
                backdrop: {
                    sx: {
                        backdropFilter: 'blur(8px)',
                        backgroundColor: 'rgba(2,6,23,0.45)',
                    },
                },
                paper: {
                    sx: {
                        borderRadius: 3,
                        backgroundImage: 'none',
                        bgcolor: 'background.paper',
                    },
                },
            }}
        >
            <DialogTitle>Unlock vault</DialogTitle>

            <DialogContent>
                <Typography variant="body2" sx={{ mb: 1 }}>
                    Enter your master password to decrypt your vault.
                </Typography>

                <TextField
                    fullWidth
                    autoFocus
                    label="Master password"
                    type={show ? 'text' : 'password'}
                    value={mp}
                    onChange={(e) => setMp(e.target.value)}
                    error={!!err}
                    helperText={err || ' '}
                    onKeyDown={(e) => {
                        if (e.key === 'Enter') onUnlock();
                    }}
                    slotProps={{
                        input: {
                            endAdornment: (
                                <InputAdornment position="end">
                                    <IconButton
                                        onClick={() => setShow((s) => !s)}
                                        edge="end"
                                        aria-label="toggle password visibility"
                                    >
                                        {show ? <VisibilityOff /> : <Visibility />}
                                    </IconButton>
                                </InputAdornment>
                            ),
                        },
                    }}
                />
            </DialogContent>

            <DialogActions>
                <Button
                    onClick={() => {
                        void onUnlock();
                    }}
                    disabled={!mp || busy}
                    variant="contained"
                    sx={{ fontWeight: 800 }}
                >
                    {busy ? 'Unlocking…' : 'Unlock'}
                </Button>
            </DialogActions>
        </Dialog>
    );
}
