import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Box from '@mui/material/Box';
import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';

import LoginCard from '../components/homePage/LoginCard';
import SignupCard from '../components/homePage/SignupCard';
import { useAuth } from '../auth/auth-context';

type Mode = 'login' | 'signup';

export default function Home() {
    const [mode, setMode] = useState<Mode>('login');
    const { user, loading, sessionRestored } = useAuth();
    const navigate = useNavigate();

    useEffect(() => {
        if (!loading && user && !sessionRestored) {
            navigate('/dashboard', { replace: true });
        }
    }, [loading, navigate, sessionRestored, user]);

    return (
        <Box
            sx={{
                minHeight: '100vh',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'center',
                bgcolor: 'background.default',
                py: 2,
            }}
        >
            <Container maxWidth="sm">
                <Box sx={{ mb: 2, textAlign: 'center' }}> {}
                    <Typography
                        variant="h5"
                        component="h1"
                        gutterBottom
                        sx={{ fontWeight: 700, color: 'text.primary', mb: 0.5 }}
                    >
                        Password Manager
                    </Typography>
                    <Typography variant="body2" color="text.secondary">
                        Secure, encrypted, and simple.
                    </Typography>
                </Box>

                <Box
                    sx={{
                        width: '100%',
                        display: 'flex',
                        justifyContent: 'center',
                    }}
                >
                    {mode === 'login' ? (
                        <LoginCard onSwitchToSignup={() => setMode('signup')} />
                    ) : (
                        <SignupCard onSwitchToLogin={() => setMode('login')} />
                    )}
                </Box>
            </Container>
        </Box>
    );
}
