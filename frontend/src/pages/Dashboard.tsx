import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import { Button, Stack, Typography } from '@mui/material';
import { useAuth } from '../auth/AuthContext';

export default function Dashboard() {
    const { user, logout } = useAuth();
    const [status, setStatus] = useState<string>('…');

    useEffect(() => {
        api.health().then(() => setStatus('OK')).catch(() => setStatus('FAIL'));
    }, []);

    return (
        <Stack spacing={2} sx={{ p: 4 }}>
            <Typography variant="h5">Welcome{user?.email ? `, ${user.email}` : ''}</Typography>
            <Typography variant="body2">API health: {status}</Typography>
            <Button variant="outlined" onClick={logout}>Log out</Button>
        </Stack>
    );
}
