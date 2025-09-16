import { useState } from 'react';
import { useAuth } from '../auth/AuthContext';
import {
    Box, Drawer, List, ListItemButton, ListItemIcon, ListItemText,
    Divider, Typography, Avatar, TextField, IconButton, Card, CardContent,
    Button, InputAdornment,
} from '@mui/material';
import { Search, AccountBox, CreditCard, Note, Wifi, Key, Assignment, Star, Edit } from '@mui/icons-material';

const categories = [
    { text: 'Logins', icon: <Key /> },
    { text: 'Secure Notes', icon: <Note /> },
    { text: 'Credit Cards', icon: <CreditCard /> },
    { text: 'Identities', icon: <AccountBox /> },
    { text: 'Software Licenses', icon: <Assignment /> },
    { text: 'Wireless Routers', icon: <Wifi /> },
];

const items = [
    { name: "Driver's License", username: 'D6101-40706-60905', url: '' },
    { name: 'Dropbox', username: 'wendy.c.appleseed@gmail.com', url: 'https://dropbox.com' },
    { name: 'E*TRADE', username: 'wendy.c.appleseed@gmail.com', url: 'https://us.etrade.com' },
    { name: 'Evernote', username: 'wendy_appleseed@agilebits.com', url: 'https://evernote.com' },
    { name: 'Facebook', username: 'wendy.c.appleseed@gmail.com', url: 'https://facebook.com' },
    { name: 'Fantastical', username: '2', url: 'https://flexibits.com/fantastical' },
    { name: 'Gift Shopping List', username: '', url: '' },
    { name: 'Google', username: 'wendy.c.appleseed@gmail.com', url: 'https://google.com' },
];

export default function Dashboard() {
    const [selected, setSelected] = useState(items[3]);
    const { user, logout } = useAuth();

    return (
        <Box display="flex" minHeight="100vh" sx={{ bgcolor: 'background.default' }}>
            <Drawer
                variant="permanent"
                anchor="left"
                slotProps={{
                    paper: {
                        sx: {
                            width: 260,
                            borderRight: '1px solid',
                            borderColor: 'divider',
                            bgcolor: 'background.paper',
                        },
                    },
                }}
            >
                <Box p={2}>
                    <Typography variant="h6" fontWeight={700} gutterBottom>
                        All Items ({items.length})
                    </Typography>
                    <Divider sx={{ mb: 2 }} />
                    <List dense>
                        {categories.map((cat) => (
                            <ListItemButton key={cat.text}>
                                <ListItemIcon sx={{ minWidth: 36 }}>{cat.icon}</ListItemIcon>
                                <ListItemText primary={cat.text} />
                            </ListItemButton>
                        ))}
                    </List>
                </Box>
            </Drawer>

            <Box flex={1} p={3} ml={{ xs: 0, md: '260px' }}>
                <Box display="flex" alignItems="center" justifyContent="space-between" mb={2} gap={2}>
                    <TextField
                        placeholder="Search"
                        size="small"
                        sx={{ maxWidth: 420 }}
                        slotProps={{
                            input: {
                                startAdornment: (
                                    <InputAdornment position="start">
                                        <Search fontSize="small" />
                                    </InputAdornment>
                                ),
                            },
                        }}
                    />
                    <Box display="flex" alignItems="center" gap={2}>
                        <Button onClick={logout} variant="outlined" size="small">
                            Log out
                        </Button>
                        <Avatar alt={user?.email ?? 'User'} src="/avatar.png" />
                        <Typography variant="body2">{user?.email ?? 'No user email found'}</Typography>
                    </Box>
                </Box>

                <Box display="grid" gridTemplateColumns={{ xs: '1fr', md: '280px 1fr' }} gap={2}>
                    <Card variant="outlined" sx={{ overflow: 'hidden' }}>
                        <List dense disablePadding>
                            {items.map((item) => {
                                const active = selected.name === item.name;
                                return (
                                    <ListItemButton
                                        key={item.name}
                                        selected={active}
                                        onClick={() => setSelected(item)}
                                        sx={{
                                            '&.Mui-selected': {
                                                bgcolor: (t) =>
                                                    t.palette.mode === 'dark'
                                                        ? 'rgba(99,102,241,.12)'
                                                        : 'rgba(99,102,241,.08)',
                                            },
                                        }}
                                    >
                                        <ListItemText primary={item.name} secondary={item.username || '—'} />
                                    </ListItemButton>
                                );
                            })}
                        </List>
                    </Card>

                    <Card sx={{ minHeight: 420 }}>
                        <CardContent>
                            <Box display="flex" justifyContent="space-between" alignItems="center" mb={1.5}>
                                <Typography variant="h6" fontWeight={700}>
                                    {selected.name}
                                </Typography>
                                <Box>
                                    <IconButton size="small">
                                        <Star color="warning" />
                                    </IconButton>
                                    <IconButton size="small">
                                        <Edit />
                                    </IconButton>
                                </Box>
                            </Box>

                            <Typography variant="caption" color="text.secondary">
                                username
                            </Typography>
                            <Typography sx={{ mb: 1 }}>{selected.username || '—'}</Typography>

                            <Typography variant="caption" color="text.secondary">
                                password
                            </Typography>
                            <Typography sx={{ mb: 1 }}>••••••••</Typography>

                            <Typography variant="caption" color="text.secondary">
                                strength
                            </Typography>
                            <Box
                                sx={{
                                    height: 8,
                                    width: 140,
                                    backgroundColor: 'action.hover',
                                    borderRadius: 4,
                                    mt: 0.5,
                                    mb: 2,
                                }}
                            >
                                <Box
                                    sx={{
                                        height: '100%',
                                        width: '40%',
                                        backgroundColor: 'success.main',
                                        borderRadius: 4,
                                    }}
                                />
                            </Box>

                            <Typography variant="caption" color="text.secondary">
                                website
                            </Typography>
                            <Box>
                                {selected.url ? (
                                    <Button href={selected.url} target="_blank" rel="noreferrer" size="small">
                                        {new URL(selected.url).hostname}
                                    </Button>
                                ) : (
                                    <Typography variant="body2" color="text.secondary">
                                        —
                                    </Typography>
                                )}
                            </Box>
                        </CardContent>
                    </Card>
                </Box>
            </Box>
        </Box>
    );
}
