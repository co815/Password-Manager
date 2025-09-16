import { useState } from 'react';
import { Dialog, DialogTitle, DialogContent, DialogActions, Button, TextField, InputAdornment, IconButton, Typography } from '@mui/material';
import Visibility from '@mui/icons-material/Visibility';
import VisibilityOff from '@mui/icons-material/VisibilityOff';
import { deriveKEK } from '../../lib/crypto/argon2';
import { unwrapDEK } from '../../lib/crypto/unwrap';
import { useCrypto } from '../../lib/crypto/CryptoContext';

export default function UnlockDialog({ open }: { open: boolean }) {
    const { setDEK } = useCrypto();
    const [mp, setMp] = useState('');
    const [show, setShow] = useState(false);
    const [busy, setBusy] = useState(false);
    const [err, setErr] = useState<string | null>(null);

    const onUnlock = async () => {
        setBusy(true); setErr(null);
        try {
            const raw = localStorage.getItem('profile');
            if (!raw) throw new Error('No profile');
            const user = JSON.parse(raw);
            const kek = await deriveKEK(mp, user.saltClient);
            const dek = await unwrapDEK(kek, user.dekEncrypted, user.dekNonce);
            setDEK(dek);
            setMp('');
        } catch (e: any) {
            setErr('Master password invalid');
        } finally {
            setBusy(false);
        }
    };

    return (
        <Dialog
            open={open}
            maxWidth="xs"
            fullWidth
            onClose={() => {}}
            disableEscapeKeyDown
            slotProps={{
                backdrop: {
                    sx: {
                        backdropFilter: 'blur(10px)',
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
                <Typography variant="body2" sx={{ mb: 1 }}>Enter your master password to decrypt your vault.</Typography>
                <TextField
                    fullWidth
                    autoFocus
                    label="Master password"
                    type={show ? 'text' : 'password'}
                    value={mp}
                    onChange={(e) => setMp(e.target.value)}
                    error={!!err}
                    helperText={err || ' '}
                    InputProps={{
                        endAdornment: (
                            <InputAdornment position="end">
                                <IconButton onClick={() => setShow(s => !s)} edge="end">
                                    {show ? <VisibilityOff /> : <Visibility />}
                                </IconButton>
                            </InputAdornment>
                        ),
                    }}
                    onKeyDown={(e) => { if (e.key === 'Enter' && !busy && mp) onUnlock(); }}
                />
            </DialogContent>
            <DialogActions>
                <Button onClick={onUnlock} disabled={!mp || busy} variant="contained">Unlock</Button>
            </DialogActions>
        </Dialog>
    );
}
