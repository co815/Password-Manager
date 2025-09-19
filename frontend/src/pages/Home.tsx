import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Info from '../components/homePage/Info';
import Auth from '../components/homePage/Auth';
import ThemeToggle from '../components/common/ThemeToggle';

export default function Home() {
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
            <ThemeToggle />

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

            <Paper
                elevation={8}
                sx={{
                    position: 'relative',
                    width: '100%',
                    maxWidth: 1100,
                    minWidth: 850,
                    height: 560,
                    borderRadius: 4,
                    overflow: 'hidden',
                    backdropFilter: 'blur(4px)',
                    border: '1px solid rgba(255,255,255,.5)',
                    boxShadow: '0 10px 40px rgba(31,41,55,.10)',
                }}
            >
                <Box
                    sx={{
                        display: 'grid',
                        gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' },
                        alignItems: 'stretch',
                        height: '100%',
                        '& > .col': {
                            p: { xs: 4, md: 5 },
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            height: '100%',
                        },
                    }}
                >
                    <Box
                        className="col"
                        sx={{
                            background: 'linear-gradient(135deg, #6366f1 0%, #06b6d4 100%)',
                            color: '#fff',
                        }}
                    >
                        <Info />
                    </Box>

                    <Box className="col">
                        <Auth fixedHeight />
                    </Box>
                </Box>
            </Paper>
        </Box>
    );
}
