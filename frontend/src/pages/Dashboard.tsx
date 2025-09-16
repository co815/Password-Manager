import { useState } from "react";

import { useAuth } from '../auth/AuthContext';
import {
    Box,
    Drawer,
    List,
    ListItemButton,
    ListItemIcon,
    ListItemText,
    Divider,
    Typography,
    Avatar,
    TextField,
    IconButton,
    Card,
    CardContent,
    Button,
} from "@mui/material";
import {
    Search,
    AccountBox,
    CreditCard,
    Note,
    Wifi,
    Key,
    Assignment,
    Star,
    Edit,
} from "@mui/icons-material";

const categories = [
    { text: "Logins", icon: <Key /> },
    { text: "Secure Notes", icon: <Note /> },
    { text: "Credit Cards", icon: <CreditCard /> },
    { text: "Identities", icon: <AccountBox /> },
    { text: "Software Licenses", icon: <Assignment /> },
    { text: "Wireless Routers", icon: <Wifi /> },
];

const items = [
    { name: "Driver's License", username: "D6101-40706-60905" },
    { name: "Dropbox", username: "wendy.c.appleseed@gmail.com" },
    { name: "E*TRADE", username: "wendy.c.appleseed@gmail.com" },
    { name: "Evernote", username: "wendy_appleseed@agilebits.com" },
    { name: "Facebook", username: "wendy.c.appleseed@gmail.com" },
    { name: "Fantastical", username: "2" },
    { name: "Gift Shopping List", username: "" },
    { name: "Google", username: "wendy.c.appleseed@gmail.com" },
];

export default function PasswordDashboard() {
    const [selected, setSelected] = useState(items[3]); // default Evernote
    const { user, logout } = useAuth();
    return (
        <Box display="flex" height="100vh">
            {/* Sidebar */}
            <Drawer variant="permanent" anchor="left">
                <Box width={240} p={2}>
                    <Typography variant="h6" gutterBottom>
                        All Items ({items.length})
                    </Typography>
                    <Divider sx={{ mb: 2 }} />
                    <List>
                        {categories.map((cat) => (
                            <ListItemButton key={cat.text}>
                                <ListItemIcon>{cat.icon}</ListItemIcon>
                                <ListItemText primary={cat.text} />
                            </ListItemButton>
                        ))}
                    </List>
                </Box>
            </Drawer>

            {/* Main Content */}
            <Box flex={1} p={3} ml={30}>
                {/* Header */}
                <Button variant="outlined" onClick={logout}>Log out</Button>
                <Box display="flex" justifyContent="space-between" alignItems="center" mb={2}>
                    <TextField
                        variant="outlined"
                        size="small"
                        placeholder="Search"
                        InputProps={{
                            startAdornment: <Search sx={{ mr: 1 }} />,
                        }}
                    />
                    <Box display="flex" alignItems="center" gap={2}>
                        <Avatar alt={user?.email ? user.email : "No user email found"} src="/avatar.png" />
                        <Typography> {user?.email ? user.email : "No user email found"} </Typography>
                    </Box>
                </Box>

                <Box display="flex">
                    {/* Items List */}
                    <Box width={250} pr={2}>
                        <List>
                            {items.map((item) => (
                                <ListItemButton
                                    key={item.name}
                                    selected={selected.name === item.name}
                                    onClick={() => setSelected(item)}
                                >
                                    <ListItemText
                                        primary={item.name}
                                        secondary={item.username}
                                    />
                                </ListItemButton>
                            ))}
                        </List>
                    </Box>

                    {/* Item Details */}
                    <Card sx={{ flex: 1 }}>
                        <CardContent>
                            <Box display="flex" justifyContent="space-between" alignItems="center">
                                <Typography variant="h6">{selected.name}</Typography>
                                <Box>
                                    <IconButton>
                                        <Star color="warning" />
                                    </IconButton>
                                    <IconButton>
                                        <Edit />
                                    </IconButton>
                                </Box>
                            </Box>
                            <Typography variant="body2" color="textSecondary">
                                username
                            </Typography>
                            <Typography>{selected.username || "—"}</Typography>

                            <Typography variant="body2" color="textSecondary" mt={2}>
                                password
                            </Typography>
                            <Typography>••••••••</Typography>

                            <Typography variant="body2" color="textSecondary" mt={2}>
                                strength
                            </Typography>
                            <Box
                                sx={{
                                    height: 8,
                                    width: "120px",
                                    backgroundColor: "#ddd",
                                    borderRadius: 4,
                                    mt: 0.5,
                                }}
                            >
                                <Box
                                    sx={{
                                        height: "100%",
                                        width: "40%",
                                        backgroundColor: "success.main",
                                        borderRadius: 4,
                                    }}
                                />
                            </Box>

                            <Typography variant="body2" color="textSecondary" mt={2}>
                                website
                            </Typography>
                            <Button href="https://www.evernote.com" target="_blank">
                                evernote.com
                            </Button>
                        </CardContent>
                    </Card>
                </Box>
            </Box>
        </Box>
    );
}