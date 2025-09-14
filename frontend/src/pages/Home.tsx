import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Info from '../components/homePage/Info';
import Auth from '../components/homePage/Auth';

export default function Home() {
    return (
        <Box
            sx={{
                minHeight: '100vh',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                background: 'linear-gradient(135deg, #e0e7ff 0%, #f0fdfa 100%)',
            }}
        >
            <Paper
                elevation={6}
                sx={{
                    borderRadius: 4,
                    overflow: 'hidden',
                    minWidth: 850,
                    width: '100%',
                    maxWidth: 1100,
                    minHeight: 400,
                }}
            >
                <Box
                    sx={{
                        display: 'grid',
                        gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' }, // 1 col pe mobil, 2 pe desktop
                        '& > .col': {
                            p: 5,
                            display: 'flex',
                            flexDirection: 'column',
                            alignItems: 'center',
                            justifyContent: 'center',
                        },
                    }}
                >
                    {/* Left: Info */}
                    <Box
                        className="col"
                        sx={{
                            background: 'linear-gradient(135deg, #6366f1 0%, #06b6d4 100%)',
                            color: '#fff',
                        }}
                    >
                        <Info />
                    </Box>

                    {/* Right: Auth (login/signup) */}
                    <Box className="col">
                        <Auth onSuccess={() => { window.location.href = '/dashboard'; }} />
                    </Box>
                </Box>
            </Paper>
        </Box>
    );
}
