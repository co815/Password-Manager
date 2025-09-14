import Box from '@mui/material/Box';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import Info from '../components/homePage/Info';
import Auth from '../components/homePage/Auth';

function Home () {
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
                <Grid container>  {/* this is the container */}
                    {/* Left: Info */}
                    <Grid
                        size={{ xs: 12, md: 6 }}  // takes full width on small screens, half on md+
                        sx={{
                            background: 'linear-gradient(135deg, #6366f1 0%, #06b6d4 100%)',
                            color: '#fff',
                            display: 'flex',
                            flexDirection: 'column',
                            justifyContent: 'center',
                            alignItems: 'center',
                            p: 5,
                        }}
                    >
                        <Info />
                    </Grid>

                    {/* Right: Auth (login/signup) */}
                    <Grid
                        size={{ xs: 12, md: 6 }}
                        sx={{
                            display: 'flex',
                            flexDirection: 'column',
                            justifyContent: 'center',
                            alignItems: 'center',
                            p: 5,
                        }}
                    >
                        <Auth />
                    </Grid>
                </Grid>
            </Paper>
        </Box>
    );
};

export default Home;
