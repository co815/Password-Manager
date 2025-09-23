import { useState } from 'react';
import Box from '@mui/material/Box';

import LoginCard from '../components/homePage/LoginCard';
import SignupCard from '../components/homePage/SignupCard';

type Mode = 'login' | 'signup';

export default function Home() {
    const [mode, setMode] = useState<Mode>('login');

    return (
        <Box
            sx={(theme) => ({
                minHeight: '100vh',
                display: 'grid',
                placeItems: 'center',
                p: { xs: 2, md: 4 },
                position: 'relative',
                overflow: 'hidden',
                background:
                    theme.palette.mode === 'dark'
                        ? `
              radial-gradient(60% 60% at 20% 10%, rgba(99,102,241,.15), transparent 60%),
              radial-gradient(50% 50% at 80% 80%, rgba(20,184,166,.12), transparent 60%),
              linear-gradient(135deg, #0b1020 0%, #11172b 100%)
            `
                        : 'linear-gradient(135deg, #eef2ff 0%, #f0fdfa 100%)',
            })}
        >
            <Box
                sx={{
                    position: 'absolute',
                    inset: -200,
                    pointerEvents: 'none',
                    background: `
            radial-gradient(400px 300px at 15% 25%, rgba(99,102,241,.20), transparent 60%),
            radial-gradient(500px 350px at 85% 75%, rgba(20,184,166,.18), transparent 60%)
          `,
                    filter: 'blur(30px)',
                }}
            />

            <Box
                sx={(theme) => ({
                    position: 'relative',
                    width: '100%',
                    maxWidth: { xs: 520, md: 560 },
                    minHeight: { xs: 'auto', md: 560 },
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    px: { xs: 2.5, sm: 4 },
                    py: { xs: 2.5, sm: 4, md: 5 },
                    borderRadius: 4,
                    overflow: 'hidden',
                    backdropFilter: 'blur(16px)',
                    border: '1px solid rgba(255,255,255,.35)',
                    boxShadow: '0 10px 40px rgba(31,41,55,.10)',
                    background:
                        theme.palette.mode === 'dark'
                            ? 'linear-gradient(135deg, rgba(15,23,42,0.86) 0%, rgba(30,41,59,0.78) 100%)'
                            : 'linear-gradient(135deg, rgba(255,255,255,0.92) 0%, rgba(224,242,254,0.88) 100%)',
                    '&::after': {
                        content: '""',
                        position: 'absolute',
                        inset: 0,
                        pointerEvents: 'none',
                        background:
                            theme.palette.mode === 'dark'
                                ? 'radial-gradient(90% 80% at 80% 18%, rgba(99,102,241,0.22), transparent 62%)'
                                : 'radial-gradient(90% 80% at 82% 20%, rgba(99,102,241,0.12), transparent 62%)',
                        mixBlendMode: theme.palette.mode === 'dark' ? 'screen' : 'multiply',
                        opacity: theme.palette.mode === 'dark' ? 1 : 0.85,
                        zIndex: 0,
                    },
                    '& > *': {
                        position: 'relative',
                        zIndex: 1,
                        width: '100%',
                    },
                })}
            >
                {mode === 'login' ? (
                    <LoginCard onSwitchToSignup={() => setMode('signup')} />
                ) : (
                    <SignupCard onSwitchToLogin={() => setMode('login')} />
                )}
            </Box>
        </Box>
    );
}
